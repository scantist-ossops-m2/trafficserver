/*
 * Implement web filter action
 */
#include <dirent.h>
#include <unistd.h>
#include <mutex>
#include <shared_mutex>
#include <fcntl.h>
#include <inttypes.h>
#include <errno.h>
#include <openssl/err.h>
#include "web_filter.h"
#include <google/protobuf/arena.h>
#include <google/protobuf/util/message_differencer.h>
#include "proto/common/types.pb.h"
#include "proto/conduit/v2/layer7.pb.h"

#include "ts/ts.h"
#include "plugin.h"
#include "policy.h"
#include "logging.h"
#include "policy_hit_counter.h"

using google::protobuf::util::MessageDifferencer;

const char *empty_string = "";

PolicyHitCounterManager policy_hit_counter_manager;
std::function<void(int, int)> send_stats_callback;

bool
isFinalPolicyResult(PolicyResult result)
{
  return result != PolicyResult::POLICY_CONTINUE && result != POLICY_INIT;
}
class PolicyHolder
{
public:
  void
  SetPolicies(Layer7Config &new_config)
  {
    Dbg(dbg_ctl, "UpdatePolicy old generation=0x%x", this->generationNumber);
    std::unique_lock<std::shared_mutex> lock(this->mutex);

    this->current_config = std::make_shared<Layer7Config>(new_config);
    auto it              = new_config.mutable_policies()->begin();
    auto offset          = policy_hit_counter_manager.CurrentOffset();
    auto length          = policy_hit_counter_manager.CurrentLength();
    auto send_old        = policy_hit_counter_manager.CreateNew(new_config.policies_size());
    uint32_t index       = 0;

    if (send_old && send_stats_callback) {
      send_stats_callback(offset, length);
    }
    while (it != new_config.mutable_policies()->end()) {
      policy_hit_counter_manager.ResetCounter(index++, it->id().a(), it->id().b());
      it++;
    }

    trafficFilters.load(new_config);
    webFilters.load(new_config);
    this->generationNumber = this->generationNumber + 1;
  }

  bool
  IsPolicySet()
  {
    std::shared_lock<std::shared_mutex> lock(this->mutex);
    return this->current_config != nullptr;
  }
  std::shared_ptr<Layer7Config>
  GetCurrentConfig()
  {
    return this->current_config;
  }
  PolicyResult internalEvaluatePolicySni(TSVConn ssl_vc, PolicyEvalInfo *policy_offset);
  PolicyResult internalEvaluatePolicyTxn(TSHttpTxn txnp, PolicyEvalInfo *policy_offset);

  std::shared_mutex &
  Mutex()
  {
    return mutex;
  }

private:
  bool logAndWatchResult(const char *stage, PolicyResult result, struct sockaddr_in *client_addr, struct sockaddr_in *server_addr,
                         const char *sni_hostname, const char *url, int policy_offset, int decrypt_policy_offset);
  PolicyResult checkAction(int policy_offset);
  MatchResult MatchTuple(int policy_offset, struct sockaddr_in *client_addr, struct sockaddr_in *server_addr);
  MatchResult MatchWebFilter(int policy_offset, std::string_view sni_target, std::string_view url_target);
  bool HasWebFilters(int policy_offset);
  bool IsLogPolicy(int policy_offset);
  bool IsWatchPolicy(int policy_offset);
  bool MeetFlowRequirements(int policy_offset, TSHttpTxn txnp);
  bool AllowsDecrypt(int policy_offset);
  void SetGenerationNumber(PolicyEvalInfo *policy_eval_info);
  int GetGenerationNumber(PolicyEvalInfo *policy_eval_info);
  void SetPolicyOffset(PolicyEvalInfo *policy_eval_info, int policy_offset);
  int GetPolicyOffset(PolicyEvalInfo *policy_eval_info);
  bool GetPolicyWatched(PolicyEvalInfo *policy_eval_info);
  void SetPolicyWatched(PolicyEvalInfo *policy_eval_info);

  mutable std::shared_mutex mutex;
  std::shared_ptr<Layer7Config> current_config;
  WebFilters webFilters;
  TrafficFilters trafficFilters;
  uint16_t generationNumber = 1;
};

PolicyHolder activePolicy;

void
PolicyHolder::SetGenerationNumber(PolicyEvalInfo *policy_eval_info)
{
  policy_eval_info->fields.generation = this->generationNumber;
  // *policy_eval_info = ((*policy_eval_info) & (~GENERATION_MASK)) | ((this->generationNumber << GENERATION_SHIFT) &
  // GENERATION_MASK);
  Dbg(dbg_ctl, "Set generation number 0x%" PRIx64 " generation=0x%x", policy_eval_info->value, this->generationNumber);
}

int
PolicyHolder::GetGenerationNumber(PolicyEvalInfo *policy_eval_info)
{
  return policy_eval_info->fields.generation;
}

void
PolicyHolder::SetPolicyOffset(PolicyEvalInfo *policy_eval_info, int policy_offset)
{
  policy_eval_info->fields.offset     = static_cast<int16_t>(policy_offset);
  policy_eval_info->fields.generation = this->generationNumber;
  //*policy_eval_info = (((this->generationNumber << GENERATION_SHIFT) & GENERATION_MASK) | (policy_offset & OFFSET_MASK));
  Dbg(dbg_ctl, "Set policy offset 0x%" PRIx64 " generation=0x%x offset=0x%x", policy_eval_info->value, this->generationNumber,
      policy_offset);
}

int
PolicyHolder::GetPolicyOffset(PolicyEvalInfo *policy_eval_info)
{
  if (policy_eval_info->fields.initialized == 0 || policy_eval_info->fields.generation != this->generationNumber) {
    Dbg(dbg_ctl, "Reset policy offset due to generation number change 0x%x to 0x%" PRIx64, this->generationNumber,
        policy_eval_info->value);
    policy_eval_info->fields.initialized = 1;
    this->SetPolicyOffset(policy_eval_info, 0);
    return 0;
  } else {
    return policy_eval_info->fields.offset;
  }
}

bool
PolicyHolder::GetPolicyWatched(PolicyEvalInfo *policy_eval_info)
{
  return policy_eval_info->fields.watched != 0;
}

void
PolicyHolder::SetPolicyWatched(PolicyEvalInfo *policy_eval_info)
{
  policy_eval_info->fields.watched = 1;
}

bool
IsPolicyLoaded()
{
  return activePolicy.IsPolicySet();
}

static std::mutex load_policy_mutex;
bool
LoadPolicy(bool skip_if_exists)
{
  std::unique_lock<std::mutex> lock(load_policy_mutex);

  auto current_config = activePolicy.GetCurrentConfig();
  if (skip_if_exists && current_config != nullptr) {
    // this is on startup, we just want a config
    // and don't care about the 2nd,3rd,etc request
    // being blocked by the lock
    return true;
  }

  Layer7Config *policyConfig = FetchLayer7Policy();
  if (policyConfig != nullptr) {
    if (current_config != nullptr) {
      // ignore duplicates
      bool isEqual = MessageDifferencer::Equals(*current_config, *policyConfig);
      if (isEqual) {
        Dbg(dbg_ctl, "Skipping policy, same");
        return true;
      }
    }
    activePolicy.SetPolicies(*policyConfig);
  }
  return policyConfig != nullptr;
}

bool
SendPolicyHitCounters(int offset, int length)
{
  google::protobuf::Arena arena;
  HitCounters hc;
  for (int c = offset; c < offset + length; c++) {
    auto counter = policy_hit_counter_manager.GetAbsoluteCounter(c);
    if (counter.hit == 0 && counter.hit_watch == 0) {
      continue;
    }

    auto tocounter = hc.add_counters();

    // UUID *id       = new UUID();
    auto id = tocounter->mutable_id();
    id->set_a(counter.id_a);
    id->set_b(counter.id_b);

    // tocounter->set_allocated_id(id);
    tocounter->set_hit(counter.hit);
    tocounter->set_hit_watch(counter.hit_watch);
    Dbg(dbg_ctl, "%" PRId64 "/%" PRId64 " %" PRId64, counter.id_a, counter.id_b, counter.hit);
  }
  Dbg(dbg_ctl, "SendPolicyHitCounters: %d", hc.counters_size());
  if (hc.counters_size() > 0) {
    auto result = SendLayer7PolicyHitCounters(hc);
    Dbg(dbg_ctl, "Result: %d %s", (int)result->result(), result->message().c_str());
    delete result;
  }
  return true;
}

void
RotatePolicyHitCounters()
{
  bool sendvalues     = false;
  uint32_t offset     = 0;
  uint32_t cur_length = 0;
  {
    std::unique_lock<std::shared_mutex> lock(activePolicy.Mutex());
    offset     = policy_hit_counter_manager.CurrentOffset();
    cur_length = policy_hit_counter_manager.CurrentLength();
    sendvalues = policy_hit_counter_manager.CopyNext();
  }
  Dbg(dbg_ctl, "RotatePolicyHitCounters: %d %d %d", offset, cur_length, (int)sendvalues);
  if (sendvalues) {
    SendPolicyHitCounters(offset, cur_length);
  }
}

int
getTupleInfo(int ssl_fd, sockaddr_in *client_addr, sockaddr_in *origin_addr)
{
  if (ssl_fd < 0) {
    auto e = ERR_get_error();
    TSError("[%s] Failed to access file descriptor for SSL object: %s fd=%x", PLUGIN_NAME, ERR_error_string(e, nullptr), ssl_fd);
    return -1;
  }
  socklen_t addr_size = sizeof(struct sockaddr_in);
  int res             = getpeername(ssl_fd, (struct sockaddr *)client_addr, &addr_size);
  if (res < 0) {
    TSError("[%s] Failed to access peer address", PLUGIN_NAME);
    return -1;
  }
  res = getsockname(ssl_fd, (struct sockaddr *)origin_addr, &addr_size);
  if (res < 0) {
    TSError("[%s] Failed to access origin address", PLUGIN_NAME);
    return -1;
  }
  return 0;
}

PolicyResult
EvaluatePolicySni(TSVConn ssl_vc, uint64_t *policy_eval_info)
{
  PolicyEvalInfo *temp = reinterpret_cast<PolicyEvalInfo *>(policy_eval_info);
  return activePolicy.internalEvaluatePolicySni(ssl_vc, temp);
}

bool
PolicyHolder::HasWebFilters(int policy_offset)
{
  if (policy_offset < this->current_config->policies_size()) {
    const Layer7Policy &policy = this->current_config->policies(policy_offset);
    return policy.web_filter_lists_size() > 0;
  }
  return false;
}

bool
PolicyHolder::IsWatchPolicy(int policy_offset)
{
  if (policy_offset < this->current_config->policies_size()) {
    const Layer7Policy &policy = this->current_config->policies(policy_offset);
    return policy.watch();
  }
  return false;
}

bool
PolicyHolder::IsLogPolicy(int policy_offset)
{
  if (policy_offset < this->current_config->policies_size()) {
    const Layer7Policy &policy = this->current_config->policies(policy_offset);
    return policy.log();
  }
  return false;
}

bool
PolicyHolder::AllowsDecrypt(int policy_offset)
{
  if (policy_offset < this->current_config->policies_size()) {
    const Layer7Policy &policy = this->current_config->policies(policy_offset);
    return policy.decrypt_policy() == Layer7Policy_DecryptPolicy_DECRYPT_ALLOWED;
  }
  return false;
}

PolicyResult
PolicyHolder::checkAction(int policy_offset)
{
  if (policy_offset < this->current_config->policies_size()) {
    const Layer7Policy &policy = this->current_config->policies(policy_offset);
    switch (policy.action()) {
    case Layer7Policy_Action_INTRUSION_DETECTION:
      return POLICY_IDS;
    case Layer7Policy_Action_PERMIT:
      return POLICY_PERMIT;
    case Layer7Policy_Action_DENY:
      return POLICY_DROP;
    default:
      return POLICY_ERROR;
    }
  }
  return POLICY_END;
}

bool
PolicyHolder::logAndWatchResult(const char *stage, PolicyResult result, struct sockaddr_in *client_addr,
                                struct sockaddr_in *server_addr, const char *sni_hostname, const char *url, int policy_offset,
                                int decrypt_policy_offset = -1)
{
  Dbg(dbg_ctl, "Entering %s %d", stage, static_cast<int>(result));
  bool log = false, watch = false;
  UUID decision_by, decrypted_by;
  bool decision_by_set = false, decrypted_by_set = false;

  if (policy_offset >= 0 && policy_offset < this->current_config->policies_size()) {
    const Layer7Policy &policy = this->current_config->policies(policy_offset);
    log                        = policy.log();
    watch                      = policy.watch();
    decision_by                = policy.id();
    decision_by_set            = true;
    Dbg(dbg_ctl, "Policy rule %s %s", stage, decision_by.DebugString().c_str());
  }

  if (!log && result != PolicyResult::POLICY_ERROR) {
    Dbg(dbg_ctl, "Fast exit %s %d", stage, static_cast<int>(result));
    return false;
  }

  if (decrypt_policy_offset >= 0 && decrypt_policy_offset < this->current_config->policies_size()) {
    const Layer7Policy &policy = this->current_config->policies(decrypt_policy_offset);

    decrypted_by     = policy.id();
    decrypted_by_set = true;
  }

  // scope the logging of the message
  {
    policy_log_message m = {};
    char decision_by_string[TS_UUID_STRING_LEN + 1];
    char decrypted_by_string[TS_UUID_STRING_LEN + 1];
    m.decision     = true;
    m.stage        = stage;
    m.priority     = policy_log_prio::log_alert;
    m.sni_hostname = sni_hostname ? sni_hostname : "";
    m.src          = client_addr;
    m.dest         = server_addr;
    m.url          = url;

    switch (result) {
    case PolicyResult::POLICY_PERMIT:
      m.action = "PERMIT";
      m.reason = "POLICY";
      break;

    case PolicyResult::POLICY_DROP:
      m.action = "DROP";
      m.reason = "POLICY";
      break;
    case PolicyResult::POLICY_ERROR:
      m.action  = "DROP";
      m.reason  = "POLICY_ERROR";
      m.message = "See tslogs";
      break;
    case PolicyResult::POLICY_IDS:
      m.action = "PERMIT";
      m.reason = "POLICY";
      // right now IDS is always decrypted
      // this will change and this logic has to
      // be changed as well
      if (!decrypted_by_set) {
        decrypted_by_set = decision_by_set;
        decrypted_by     = decision_by;
      }
      m.ids = true;
      break;
    case PolicyResult::POLICY_CONTINUE:
      // this should not happen
      return false;
    default:
      // should not happen
      m.action  = "DROP";
      m.reason  = "UNEXPECTED_ERROR";
      m.message = "See tslogs";
      break;
    }
    if (decision_by_set) {
      sprint_uuid(decision_by_string, decision_by.a(), decision_by.b());
      m.decided_by = decision_by_string;
    }
    if (decrypted_by_set) {
      sprint_uuid(decrypted_by_string, decrypted_by.a(), decrypted_by.b());
      m.decrypted_by = decrypted_by_string;
    }

    m.enforced = !watch;
    Dbg(dbg_ctl, "Logging now");
    policy_log(m);
  }
  return true;
}

PolicyResult
PolicyHolder::internalEvaluatePolicySni(TSVConn ssl_vc, PolicyEvalInfo *policy_eval_info)
{
  // Get the tuple info
  struct sockaddr_in client_addr, origin_addr;
  bool address_fail = true;

  int server_name_length  = 0;
  const char *server_name = TSVConnSslSniGet(ssl_vc, &server_name_length);
  if (getTupleInfo(TSVConnFdGet(ssl_vc), &client_addr, &origin_addr) < 0) {
    Dbg(dbg_ctl, "Failed to get tuple");
    logAndWatchResult("SNI", POLICY_ERROR, address_fail ? nullptr : &client_addr, address_fail ? nullptr : &origin_addr,
                      server_name, nullptr, -1, -1);
    return POLICY_ERROR;
  }

  address_fail = false;

  std::string_view sni_view;
  std::string_view empty_url_view;

  if (server_name != nullptr) {
    sni_view = std::string_view(server_name);
  } else {
    // MatchWebFilter does not like nullptrs
    sni_view = std::string_view(empty_string);
  }

  std::shared_lock<std::shared_mutex> lock(this->mutex);
  if (policy_eval_info->fields.initialized == 0) {
    policy_eval_info->fields.initialized = 1;
  }
  this->SetGenerationNumber(policy_eval_info);
  int policy_offset = this->GetPolicyOffset(policy_eval_info);
  for (int i = policy_offset; i < this->current_config->policies_size(); i++) {
    auto watch_policy = IsWatchPolicy(i);
    // move to next policy if we reported a watched policy earlier
    // no need to evaluate
    if (watch_policy && GetPolicyWatched(policy_eval_info)) {
      continue;
    }

    PolicyResult result = PolicyResult::POLICY_INIT;
    auto tuple_result   = this->MatchTuple(i, &client_addr, &origin_addr);
    if (tuple_result == MatchValues) {
      Dbg(dbg_ctl, "Match tuple");
      // Check the SNI
      auto web_filter_result = this->MatchWebFilter(i, sni_view, empty_url_view);
      if (web_filter_result == MatchValues) {
        Dbg(dbg_ctl, "Match SNI");
        result = this->checkAction(i);
      } else if (web_filter_result == NoAttributeToMatch) {
        if (this->HasWebFilters(i)) {
          Dbg(dbg_ctl, "Evaluate URL filter");
          // Are we allowed to decrypt, if not fail now
          if (!this->AllowsDecrypt(i)) {
            Dbg(dbg_ctl, "Decrypt is not allowed, drop");
            result = POLICY_DROP;
            // The web filters must be for URL
          } else if (i >= this->current_config->policies_size()) {
            result = POLICY_END;
          } else {
            result = POLICY_CONTINUE;
          }
        } else {
          // Otherwise there were no web_filters on this rule, so we are done
          Dbg(dbg_ctl, "No SNI filter");
          result = this->checkAction(i);
        }
      } // Otherwise, look at the next policy
    } else if (tuple_result != NotMatchValues) {
      Dbg(dbg_ctl, "Does not match tuple");
      result = POLICY_ERROR; // Shouldn't get here
    } else {
      Dbg(dbg_ctl, "Not match policy=%d/0x%" PRIx64, i, policy_eval_info->value);
    }

    // did not get a result, move on to the next policy
    if (result == POLICY_INIT) {
      continue;
    }

    // only log final results
    if (isFinalPolicyResult(result)) {
      if (watch_policy) {
        policy_hit_counter_manager.HitWatch(i);
      } else {
        policy_hit_counter_manager.Hit(i);
      }
      if (IsLogPolicy(i)) {
        logAndWatchResult("SNI", result, address_fail ? nullptr : &client_addr, address_fail ? nullptr : &origin_addr, server_name,
                          nullptr, i);
      }
    }
    // continue evaluating if it is
    // a watch policy (watch=true is enforced=false)
    if (watch_policy && result != PolicyResult::POLICY_CONTINUE) {
      SetPolicyWatched(policy_eval_info);
      continue;
    }

    SetPolicyOffset(policy_eval_info, i);
    return result;
  }
  // Ran out of rules before a match
  Dbg(dbg_ctl, "No matching policy");
  SetPolicyOffset(policy_eval_info, -1);
  logAndWatchResult("SNI", POLICY_END, address_fail ? nullptr : &client_addr, address_fail ? nullptr : &origin_addr, server_name,
                    nullptr, -1);
  return POLICY_END;
}

PolicyResult
EvaluatePolicyTxn(TSHttpTxn txnp, uint64_t *policy_eval_info)
{
  PolicyEvalInfo *temp = reinterpret_cast<PolicyEvalInfo *>(policy_eval_info);
  return activePolicy.internalEvaluatePolicyTxn(txnp, temp);
}

bool
PolicyHolder::MeetFlowRequirements(int policy_offset, TSHttpTxn txnp)
{
  if (policy_offset >= this->current_config->policies_size() || policy_offset < 0) {
    Dbg(dbg_ctl, "FlowRequirements: No rule offset=%d size=%d", policy_offset, this->current_config->policies_size());
    return false;
  }
  const Layer7Policy &policy = this->current_config->policies(policy_offset);
  // Is this required to be TLS?
  if (policy.flow_app_requirement() == Layer7Policy_FlowApp_TLS_REQUIRED) {
    TSHttpSsn ssnp = TSHttpTxnSsnGet(txnp);
    if (ssnp == nullptr) {
      TSError("[%s] Failed to access Txn Session", PLUGIN_NAME);
      return false;
    }
    TSVConn vc = TSHttpSsnClientVConnGet(ssnp);
    if (vc == nullptr) {
      TSError("[%s] Failed to access Txn connection", PLUGIN_NAME);
      return false;
    }
    bool retval = TSVConnIsSsl(vc);
    Dbg(dbg_ctl, "Enforce TLS test=%d", retval);
    return retval;
  }
  return true; // Don't care if this is TLS
}

PolicyResult
PolicyHolder::internalEvaluatePolicyTxn(TSHttpTxn txnp, PolicyEvalInfo *policy_eval_info)
{
  // Get the tuple info
  struct sockaddr_in client_addr, origin_addr;
  std::string s_sni_hostname; // need to rewrite policy_log to string_view instead of const char *
  std::string s_url;          // see above
  PolicyResult result = PolicyResult::POLICY_ERROR;
  int fd              = -1;

  if (TSHttpTxnClientFdGet(txnp, &fd) == TS_SUCCESS) {
    if (getTupleInfo(fd, &client_addr, &origin_addr) < 0) {
      // todo: we should report decrypted_by here, but can not as we're not in the lock
      logAndWatchResult("txn", POLICY_ERROR, nullptr, nullptr, nullptr, nullptr, -1, -1);
      return POLICY_ERROR;
    }
  } else {
    TSError("[%s] Failed to access Txn Client file descriptor", PLUGIN_NAME);
    // todo: we should report decrypted_by here, but can not as we're not in the lock
    logAndWatchResult("txn", POLICY_ERROR, nullptr, nullptr, nullptr, nullptr, -1, -1);
    return POLICY_ERROR;
  }

  std::string_view sni_view;
  sni_view = std::string_view(empty_string);
  TSMBuffer mbuf;
  TSMLoc hdr_loc;
  if (TS_SUCCESS == TSHttpTxnClientReqGet(txnp, &mbuf, &hdr_loc)) {
    int host_len     = 0;
    const char *host = TSHttpHdrHostGet(mbuf, hdr_loc, &host_len);
    if (host != nullptr) {
      sni_view       = std::string_view(host, host_len);
      s_sni_hostname = std::string(sni_view); // todo: policy_log needs to take string views
    }
  }

  int url_len     = 0;
  const char *url = TSHttpTxnEffectiveUrlStringGet(txnp, &url_len);
  if (url == nullptr || url_len <= 0) {
    TSError("[%s] Failed load URLx", PLUGIN_NAME);
    // todo: we should report decrypted_by here, but can not as we're not in the lock
    logAndWatchResult("txn", POLICY_ERROR, &client_addr, &origin_addr, s_sni_hostname.c_str(), nullptr, -1, -1);
    return POLICY_ERROR;
  }

  std::string_view url_view(url, url_len);
  s_url = std::string(url_view);

  Dbg(dbg_ctl, "Evaluate with FQDN=%.*s and URL=%.*s", static_cast<int>(sni_view.length()), sni_view.data(),
      static_cast<int>(url_view.length()), url_view.data());
  std::shared_lock<std::shared_mutex> lock(this->mutex);
  // Cross check the generation number
  int policy_offset = 0, decrypted_by = -1;

  if (policy_eval_info->fields.initialized) {
    if (this->generationNumber == GetGenerationNumber(policy_eval_info)) {
      policy_offset = this->GetPolicyOffset(policy_eval_info);
      decrypted_by  = policy_offset;
    }
  }

  Dbg(dbg_ctl, "incoming policy_offset: %d, decryption offset:%d", policy_offset, decrypted_by);
  for (int i = policy_offset; i < this->current_config->policies_size(); i++) {
    auto watch_policy = IsWatchPolicy(i);
    // move to next policy if we reported a watched policy earlier
    // no need to evaluate, we can do this early
    if (watch_policy && GetPolicyWatched(policy_eval_info)) {
      continue;
    }

    if (!this->MeetFlowRequirements(i, txnp)) {
      // Does not match the TLS requirement, try the next rule
      continue;
    }
    auto tuple_result = this->MatchTuple(i, &client_addr, &origin_addr);
    if (tuple_result == MatchValues) {
      // Check the SNI
      auto web_filter_result = this->MatchWebFilter(i, sni_view, url_view);
      if (web_filter_result == MatchValues || web_filter_result == NoAttributeToMatch) {
        result = this->checkAction(i);

        // need this for logging
        if (isFinalPolicyResult(result)) {
          if (watch_policy) {
            policy_hit_counter_manager.HitWatch(i);
          } else {
            policy_hit_counter_manager.Hit(i);
          }

          if (IsLogPolicy(i)) {
            logAndWatchResult("txn", result, &client_addr, &origin_addr, s_sni_hostname.c_str(), s_url.c_str(), i, decrypted_by);
          }
        }
        // continue evaluating if it is
        // a watch policy (watch=true is enforced=false)
        if (watch_policy) {
          SetPolicyWatched(policy_eval_info);
          continue;
        }
        TSfree(const_cast<void *>(reinterpret_cast<const void *>(url)));
        return result;
      }
    }
  }
  // Ran out of rules before a match

  logAndWatchResult("txn", POLICY_END, &client_addr, &origin_addr, s_sni_hostname.c_str(), s_url.c_str(), -1, decrypted_by);
  TSfree(const_cast<void *>(reinterpret_cast<const void *>(url)));
  return POLICY_END;
}

MatchResult
PolicyHolder::MatchWebFilter(int policy_offset, std::string_view sni_view, std::string_view url_view)
{
  if (policy_offset >= this->current_config->policies_size() || policy_offset < 0) {
    Dbg(dbg_ctl, "No rule offset=%d size=%d", policy_offset, this->current_config->policies_size());
    return NoRuleToMatch;
  }
  const Layer7Policy &policy = this->current_config->policies(policy_offset);
  if (policy.web_filter_lists_size() <= 0) {
    Dbg(dbg_ctl, "No web filter list %d policy=%d", policy.web_filter_lists_size(), policy_offset);
    return NoAttributeToMatch;
  }
  // If there are multiple web filter lists, must match every list
  for (int i = 0; i < policy.web_filter_lists_size(); i++) {
    auto list = policy.web_filter_lists(i);
    Dbg(dbg_ctl, "Check web list %d", i);
    bool found_match = false;
    for (int j = 0; j < list.web_filter_list_size(); j++) {
      auto id = list.web_filter_list(j);
      Dbg(dbg_ctl, "Check inner web list %d id=%" PRId64 " %" PRId64, j, id.a(), id.b());
      auto result = this->webFilters.match(id, sni_view, url_view);
      if (result == MatchValues) {
        found_match = true;
        break;
      } else if (result == NoAttributeToMatch) {
        // Wrong type, return immediately
        return NoAttributeToMatch;
      }
    }
    if (!found_match) {
      return NotMatchValues;
    }
  }
  // Made it through all lists, must match
  return MatchValues;
}

MatchResult
PolicyHolder::MatchTuple(int policy_offset, struct sockaddr_in *client_addr, struct sockaddr_in *server_addr)
{
  if (policy_offset >= this->current_config->policies_size() || policy_offset < 0) {
    return NoRuleToMatch;
  }
  MatchResult src_retval = NotMatchValues;
  MatchResult dst_retval = NotMatchValues;

  const Layer7Policy &policy = this->current_config->policies(policy_offset);

  if (policy.src_filters_size() == 0) {
    src_retval = MatchValues;
  }
  if (policy.dst_filters_size() == 0) {
    dst_retval = MatchValues;
  }
  // Must match at least one of the src filters and one of the dst_filters
  for (int i = 0; i < policy.src_filters_size(); i++) {
    auto id = policy.src_filters(i);
    if (this->trafficFilters.match(id, client_addr) == MatchValues) {
      Dbg(dbg_ctl, "Match src");
      src_retval = MatchValues;
      break;
    }
  }
  for (int i = 0; i < policy.dst_filters_size(); i++) {
    auto id = policy.dst_filters(i);
    if (this->trafficFilters.match(id, server_addr) == MatchValues) {
      Dbg(dbg_ctl, "Match dst");
      dst_retval = MatchValues;
      break;
    }
  }
  if (src_retval != MatchValues || dst_retval != MatchValues) {
    Dbg(dbg_ctl, "One side doesn't match");
    return NotMatchValues;
  }

  // Check the protocol and ports
  if (policy.protocol() != Layer7Policy_Protocol_PROTOCOL_UNSPECIFIED) {
    if (policy.protocol() == Layer7Policy_Protocol_TCP) {
      if (policy.port_ranges_size() > 0) {
        bool found_match = false;
        for (int i = 0; i < policy.port_ranges_size(); i++) {
          const PortRange &pr = policy.port_ranges(i);
          Dbg(dbg_ctl, "Compare port %d against %d-%d", ntohs(server_addr->sin_port), pr.lo(), pr.hi());
          if ((pr.lo() <= ntohs(server_addr->sin_port)) && (pr.hi() == 0 || pr.hi() >= ntohs(server_addr->sin_port))) {
            found_match = true;
            break;
          }
        }
        if (!found_match) {
          Dbg(dbg_ctl, "Found no port match %d ports", policy.port_ranges_size());
          return NotMatchValues;
        }
      }
    } else {
      Dbg(dbg_ctl, "Policy not TCP %d", policy.protocol());
      return NotMatchValues;
    }
  }
  return MatchValues;
}

WebFilterImpl::WebFilterImpl(WebFilter &wb)
{
  switch (wb.target()) {
  case WebFilter_FilterTarget_TARGET_SNI:
    this->type = SniFilter;
    break;
  case WebFilter_FilterTarget_TARGET_URL:
    this->type = UrlFilter;
    break;
  default:
    break;
  }
  this->name = wb.name();
  Dbg(dbg_ctl, "Load filter %s type %d", this->name.c_str(), this->type);
  for (int i = 0; i < wb.filter_match_size(); i++) {
    auto filter_match = wb.filter_match(i);
    if (filter_match.length() > 0) {
      if (filter_match[0] == '*') {
        if (filter_match.length() > 1) {
          this->suffix_partial_match[filter_match.substr(1)] = true;
        } else {
          this->match_all = true;
        }
      } else if (filter_match[filter_match.length() - 1] == '*') {
        this->prefix_partial_match[filter_match.substr(0, filter_match.length() - 1)] = true;
      } else {
        this->complete_match[filter_match] = true;
      }
    }
  }
}

MatchResult
WebFilterImpl::match(std::string_view sni_target, std::string_view url_target)
{
  std::string_view match_target;
  if (this->type == SniFilter) {
    match_target = sni_target;
  } else {
    if (url_target.length() == 0) {
      Dbg(dbg_ctl, "Filter type %d name %s", this->type, this->name.c_str());
      // Don't have input to exercise the URL filter
      return NoAttributeToMatch;
    }
    match_target = url_target;
  }
  std::string match_key(match_target.data(), match_target.length());
  Dbg(dbg_ctl, "Check %s against filter %s", match_key.c_str(), this->name.c_str());
  if (this->complete_match.find(match_key) != this->complete_match.end()) {
    Dbg(dbg_ctl, "Complete match");
    return MatchValues; // A complete match
  }
  if (this->type == SniFilter) {
    // Pull off prefixes and look for partial match
    if (this->match_all) {
      Dbg(dbg_ctl, "Wildcard * match %s", match_key.c_str());
      return MatchValues; // webfilter has a '*' entry
    }
    auto offset = match_key.find('.');
    while (offset != std::string::npos) {
      match_key = match_key.substr(offset);
      if (this->suffix_partial_match.find(match_key) != this->suffix_partial_match.end()) {
        Dbg(dbg_ctl, "Partial match %s", match_key.c_str());
        return MatchValues; // A partial match
      }
      match_key = match_key.substr(1);
      offset    = match_key.find('.');
    }
  } // Need to figure out how to evaluate the URL partial match
  return NotMatchValues;
}

bool
WebFilters::load(Layer7Config &config)
{
  bool retval = false;
  // Delete the old data
  for (auto iter = web_filter_map.begin(); iter != web_filter_map.end(); ++iter) {
    delete iter->second;
  }
  this->web_filter_map.clear();
  for (int i = 0; i < config.web_filters_size(); i++) {
    auto wb = config.web_filters(i);
    if (wb.has_id()) {
      WebFilterImpl *newWebFilter = new WebFilterImpl(wb);
      if (newWebFilter != nullptr) {
        std::pair<uint64_t, uint64_t> key;
        key.first  = wb.id().a();
        key.second = wb.id().b();
        Dbg(dbg_ctl, "Load filter %" PRId64 " %" PRId64, wb.id().a(), wb.id().b());
        web_filter_map.insert(std::make_pair(key, newWebFilter));
      }
    }
  }
  return retval;
}

MatchResult
WebFilters::match(UUID &uuid, std::string_view sni_input, std::string_view url_input)
{
  std::pair<uint64_t, uint64_t> key;
  key.first  = uuid.a();
  key.second = uuid.b();
  auto ptr   = web_filter_map.find(key);
  if (ptr != web_filter_map.end()) {
    return ptr->second->match(sni_input, url_input);
  }
  Dbg(dbg_ctl, "Did not find filter.");
  return NoAttributeToMatch;
}

TrafficFilterImpl::TrafficFilterImpl(MicrosegTrafficFilter &tf)
{
  for (int i = 0; i < tf.cidrs_size(); i++) {
    auto cidr = tf.cidrs(i);
    Dbg(dbg_ctl, "Add 0x%x / %d", cidr.addr().v4(), cidr.prefix_len());
    swoc::IP4Net ip_cidr(swoc::IP4Addr(cidr.addr().v4()), swoc::IPMask(cidr.prefix_len()));
    lookup_map.mark(ip_cidr.as_range(), true);
  }
}

bool
TrafficFilters::load(Layer7Config &config)
{
  bool retval = false;
  // Delete the old data
  for (auto iter = this->traffic_filter_map.begin(); iter != this->traffic_filter_map.end(); ++iter) {
    delete iter->second;
  }
  this->traffic_filter_map.clear();
  for (int i = 0; i < config.filters_size(); i++) {
    auto tf = config.filters(i);
    if (tf.has_id()) {
      TrafficFilterImpl *newTrafficFilter = new TrafficFilterImpl(tf);
      if (newTrafficFilter != nullptr) {
        std::pair<uint64_t, uint64_t> key;
        key.first               = tf.id().a();
        key.second              = tf.id().b();
        traffic_filter_map[key] = newTrafficFilter;
      }
    }
  }
  return retval;
}

MatchResult
TrafficFilterImpl::match(const sockaddr_in *sock_addr)
{
  Dbg(dbg_ctl, "Lookup %x", ntohl(sock_addr->sin_addr.s_addr));
  if (this->lookup_map.find(swoc::IP4Addr(sock_addr)) != this->lookup_map.end()) {
    return MatchValues;
  } else {
    return NotMatchValues;
  }
}

MatchResult
TrafficFilters::match(UUID &uuid, struct sockaddr_in *addr)
{
  std::pair<uint64_t, uint64_t> key;
  key.first  = uuid.a();
  key.second = uuid.b();
  auto ptr   = traffic_filter_map.find(key);
  if (ptr != traffic_filter_map.end()) {
    return ptr->second->match(addr);
  }
  return NotMatchValues;
}

PolicyHolder ActivePolicy;
