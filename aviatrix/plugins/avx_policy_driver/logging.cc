#include <netinet/in.h>
#include <syslog.h>
#include <ts/ts.h>
#include <inttypes.h>

#include <string>
#include "logging.h"
#include "jsonwriter.h"
#include "plugin.h"

union raw_uuid {
  uint64_t data[2];

  struct {
    uint32_t timeLow;
    uint16_t timeMid;
    uint16_t timeHighAndVersion;
    uint8_t clockSeqAndReserved;
    uint8_t clockSeqLow;
    uint8_t node[6];
  };
};

bool
sprint_uuid(char *buf, uint64_t a, uint64_t b)
{
  int len = snprintf(buf, TS_UUID_STRING_LEN + 1, "%08" PRIx64 "-%04" PRIx64 "-%04" PRIx64 "-%04" PRIx64 "-%012" PRIx64, a >> 32,
                     (a >> 16 & 0xffff), (a & 0xffff), b >> 48, (b & 0xffffffffffff));
  return (len == TS_UUID_STRING_LEN);
}

const char *priorities[] = {"LOG_EMERG",   "LOG_ALERT",  "LOG_CRIT", "LOG_ERROR",
                            "LOG_WARNING", "LOG_NOTICE", "LOG_INFO", "LOG_DEBUG"};
__attribute__((noinline)) void
policy_log(policy_log_message &msg)
{
  char jsonmessage[8192]; // should be safe on the stack
  char ip[128];
  jsonwriter w(jsonmessage, 8192);

  if (msg.priority == policy_log_prio::log_emerg || msg.priority < 0 || msg.priority > policy_log_prio::log_info) {
    msg.priority = policy_log_prio::log_info;
  }
  w.open_object();
  w.addpair("priority", priorities[msg.priority]);
  w.addpair("action", msg.action);
  w.addpair("reason", msg.reason);
  if (msg.src != nullptr) {
    w.addpair("src", TSIPNToP((sockaddr *)msg.src, ip, 128));
    w.addpair("src_port", ntohs(msg.src->sin_port));
  }
  if (msg.dest != nullptr) {
    w.addpair("dest", TSIPNToP((sockaddr *)msg.dest, ip, 128));
    w.addpair("dest_port", ntohs(msg.dest->sin_port));
  }
  w.addpair("enforced", msg.enforced);
  w.addpair("ids", msg.ids);
  w.addpair("errorcode", msg.errorcode);
  w.addpair("message", msg.message);
  w.addpair("stage", msg.stage);
  w.addpair("sni_hostname", msg.sni_hostname);
  w.addpair("decrypted_by", msg.decrypted_by);
  w.addpair("decided_by", msg.decided_by);
  // fixed value for now
  w.addpair("proto", "TCP");
  if (msg.url) {
    // fix this to stringview
    std::string url(msg.url);
    if (url.length() > 4096) {
      url = url.substr(0, 4093) + "...";
    }
    w.addpair("url", url.c_str());
  }

  w.addpair("timestamp", msg.timestamp != 0 ? msg.timestamp : time(nullptr));

  w.close_object();
  syslog(msg.priority, "%s", jsonmessage);
  Dbg(dbg_ctl, "syslog: %s", jsonmessage);
}
