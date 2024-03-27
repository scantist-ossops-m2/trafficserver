/** @file

  An example program that does a null transform of response body content.

  @section license License

  Licensed to the Apache Software Foundation (ASF) under one
  or more contributor license agreements.  See the NOTICE file
  distributed with this work for additional information
  regarding copyright ownership.  The ASF licenses this file
  to you under the Apache License, Version 2.0 (the
  "License"); you may not use this file except in compliance
  with the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
 */

// Copyright (c) 2023, Aviatrix Systems, Inc. All rights reserved.

#include <stdio.h>
#include <unistd.h>
#include <inttypes.h>
#include <string.h>
#include <errno.h>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "ts/ts.h"
#include "plugin.h"
#include "web_filter.h"
#include "policy.h"
#include "logging.h"

void RunTest(struct sockaddr_in *src_addr, struct sockaddr_in *dst_addr);

int data_arg_index = -1;

const char *L7PolicyTag        = "L7Policy";
int L7PolicyIndex              = -1;
const char *IDSPolicyTag       = "IDSPolicy";
int IDSPolicyIndex             = -1;
int IDSPolicyTxnIndex          = -1;
const char *CertifierPolicyTag = "CertifierPolicy";
int CertifierPolicyIndex       = -1;

namespace avx_policy_dirver
{
const char PLUGIN_NAME[] = "policy_driver";
DbgCtl dbg_ctl{PLUGIN_NAME};
} // namespace avx_policy_dirver

bool
register_arg_indices()
{
  if (TS_SUCCESS != TSUserArgIndexReserve(TS_USER_ARGS_VCONN, L7PolicyTag, "L7 policy", &L7PolicyIndex)) {
    TSError("Failed to register L7 policy index");
    return false;
  }
  if (TS_SUCCESS != TSUserArgIndexReserve(TS_USER_ARGS_VCONN, IDSPolicyTag, "IDS policy", &IDSPolicyIndex)) {
    TSError("Failed to register IDS connection policy index");
    return false;
  }
  if (TS_SUCCESS != TSUserArgIndexReserve(TS_USER_ARGS_TXN, IDSPolicyTag, "IDS policy", &IDSPolicyTxnIndex)) {
    TSError("Failed to register IDS transaction policy index");
    return false;
  }
  if (TS_SUCCESS != TSUserArgIndexReserve(TS_USER_ARGS_VCONN, CertifierPolicyTag, "Certifier policy", &CertifierPolicyIndex)) {
    TSError("Failed to register Certifier policy index");
    return false;
  }
  return true;
}

static int
filter_load(TSCont cont, TSEvent event, void *edata)
{
  if (TS_EVENT_LIFECYCLE_MSG == event) {
    Dbg(dbg_ctl, "Load web filter");
  }
  if (TS_EVENT_LIFECYCLE_PORTS_INITIALIZED == event) {
    Dbg(dbg_ctl, "Load web filter at process start");
  }
  if (!LoadPolicy(false)) {
    TSError("[%s] Failed to reload policy", PLUGIN_NAME);
    return TS_ERROR;
  }
  return TS_SUCCESS;
}

uint64_t
get_l7_policy_offset(TSHttpTxn txnp)
{
  TSHttpSsn ssnp = TSHttpTxnSsnGet(txnp);
  if (ssnp != nullptr) {
    TSVConn vc = TSHttpSsnClientVConnGet(ssnp);
    return reinterpret_cast<uintptr_t>(TSUserArgGet(vc, L7PolicyIndex));
  }
  // todo: precompute value
  return 0;
}

static int
policy_sni(TSCont cont, TSEvent event, void *edata)
{
  TSVConn ssl_vc          = reinterpret_cast<TSVConn>(edata);
  int server_name_length  = 0;
  const char *server_name = TSVConnSslSniGet(ssl_vc, &server_name_length);
  Dbg(dbg_ctl, "SNI filter %s", server_name);

  // Evalulate policy
  uint64_t policy_offset = 0;
  // Should return information about whether logging is required.
  auto result = EvaluatePolicySni(ssl_vc, &policy_offset);
  switch (result) {
  case POLICY_PERMIT:
    Dbg(dbg_ctl, "No IDS policy, tunnel");
    TSVConnTunnel(ssl_vc);
    break;
  case POLICY_IDS:
    Dbg(dbg_ctl, "IDS policy, continue");
    TSUserArgSet(ssl_vc, IDSPolicyIndex, reinterpret_cast<void *>(static_cast<intptr_t>(1)));
    TSUserArgSet(ssl_vc, CertifierPolicyIndex, reinterpret_cast<void *>(static_cast<intptr_t>(1)));
    Dbg(dbg_ctl, "Policy_ids set offset 0x%" PRIx64 " vc=0x%p", policy_offset, ssl_vc);
    TSUserArgSet(ssl_vc, L7PolicyIndex, reinterpret_cast<void *>(static_cast<uintptr_t>(policy_offset)));
    // Continue processing
    TSVConnReenable(ssl_vc);
    break;
  case POLICY_CONTINUE:
    // Set the policy offet and continue
    // The TXN hook should catch it
    Dbg(dbg_ctl, "Policy_continue set offset 0x%" PRIx64 " vc=0x%p", policy_offset, ssl_vc);
    TSUserArgSet(ssl_vc, L7PolicyIndex, reinterpret_cast<void *>(static_cast<uintptr_t>(policy_offset)));
    // Let the certifier know it should terminate the client connection
    TSUserArgSet(ssl_vc, CertifierPolicyIndex, reinterpret_cast<void *>(static_cast<intptr_t>(1)));
    TSVConnReenable(ssl_vc);
    break;
  case POLICY_DROP:
  default:
    Dbg(dbg_ctl, "Filter drop");
    // int ssl_fd = TSVConnFdGet(ssl_vc);
    //  close(ssl_fd);
    //  One might think that the TSVConnClose would be more appropriate
    //  than just closing the file descriptor.  But calling TSVConnClose
    //  with or without the reenable just causes a core dump.  Presume it is a problem
    //  that TSVConnClose frees of data structure that are needed to wind down the state machine
    //  TSVConnClose(ssl_vc);
    TSVConnReenable(ssl_vc);
    break;
  }
  return TS_SUCCESS;
}

static int
transaction_start(TSCont cont, TSEvent event, void *edata)
{
  TSHttpTxn txnp = reinterpret_cast<TSHttpTxn>(edata);
  // Is a policy loaded?
  if (!IsPolicyLoaded()) {
    // Big error if not
    TSError("[%s] Policy not loaded at Txn Hdr", PLUGIN_NAME);
    TSHttpTxnReenable(txnp, TS_EVENT_HTTP_ERROR);
    return TS_ERROR;
  }

  // Is there more policy to interpret
  uint64_t policy_offset = get_l7_policy_offset(txnp);
  Dbg(dbg_ctl, "Txn Policy Offset=0x%" PRIX64, policy_offset);
  auto result = EvaluatePolicyTxn(txnp, &policy_offset);
  switch (result) {
  case POLICY_PERMIT:
    Dbg(dbg_ctl, "No IDS policy, permit the translation and move on");
    TSHttpTxnReenable(txnp, TS_EVENT_HTTP_CONTINUE);
    break;
  case POLICY_IDS:
    Dbg(dbg_ctl, "IDS policy, continue");
    TSUserArgSet(txnp, IDSPolicyTxnIndex, reinterpret_cast<void *>(static_cast<intptr_t>(1)));
    // Continue processing
    TSHttpTxnReenable(txnp, TS_EVENT_HTTP_CONTINUE);
    break;
  case POLICY_DROP:
  default:
    Dbg(dbg_ctl, "URL Filter drop");
    // TODO, I assume continuing with ERROR will cause the transaction to fail
    // This will end up returning a 50x status code, we could replace this with a 401
    // unauthorized or something configurable to the customer's pleasing.  We would need to
    // set a hook on the send client response to adjust the status code and message.
    TSHttpTxnReenable(txnp, TS_EVENT_HTTP_ERROR);
    return TS_ERROR;
    break;
  }
  return TS_SUCCESS;
}

static int
connection_start(TSCont cont, TSEvent event, void *edata)
{
  TSVConn ssl_vc = reinterpret_cast<TSVConn>(edata);
  // Is a policy loaded?
  if (!IsPolicyLoaded()) {
    // LoadPolicy, but skip config request if we get a policy in the meantime
    // this is to prevent thundering herd DOS at the state sync service
    if (!LoadPolicy(true)) {
      TSError("[%s] Failed to load policy", PLUGIN_NAME);
      TSVConnReenable(ssl_vc);
      return TS_ERROR;
    }
  }
  // Set up the hooks for transactions on this session
  // Potentially SNI and client request request

  TSVConnReenable(ssl_vc);
  return TS_SUCCESS;
}

static int
send_stats(TSCont cont, TSEvent event, void *edata)
{
  Dbg(dbg_ctl, "Entering send_stats");
  auto data = reinterpret_cast<uint64_t>(TSContDataGet(cont));
  if (data) {
    Dbg(dbg_ctl, "send_stats: %" PRId64, data);
    int offset = data >> 32;
    int length = data & 0xffffffff;
    SendPolicyHitCounters(offset, length);
    TSContDestroy(cont);
  } else {
    Dbg(dbg_ctl, "send_stats: rotating");
    RotatePolicyHitCounters();
  }
  return TS_SUCCESS;
}

void
TSPluginInit(int argc, const char *argv[])
{
  TSPluginRegistrationInfo info;

  info.plugin_name   = PLUGIN_NAME;
  info.vendor_name   = "Aviatrix";
  info.support_email = "dev@trafficserver.apache.org";

  if (TSPluginRegister(&info) != TS_SUCCESS) {
    TSError("[%s] Plugin registration failed", PLUGIN_NAME);

  } else {
    if (argc < 3) {
      TSError("[%s] Plugin failed. Requires argument <policy server port stats_interval_seconds >", PLUGIN_NAME);
      return;
    }
    // we need to make this configurable by the localgateway config
    // and environment
    int stats_timeout = atoi(argv[2]);
    if (stats_timeout <= 0) {
      stats_timeout = 60;
    }
    TSCont start_contp     = TSContCreate(connection_start, NULL);
    TSCont start_txn_contp = TSContCreate(transaction_start, NULL);
    // Trigger on connection start, apply hooks on txn start as necssary
    TSHttpHookAdd(TS_VCONN_START_HOOK, start_contp);
    TSHttpHookAdd(TS_HTTP_READ_REQUEST_HDR_HOOK, start_txn_contp);
    // Set up next hook
    TSCont cb_sni = TSContCreate(policy_sni, nullptr);
    TSHttpHookAdd(TS_SSL_CERT_HOOK, cb_sni);

    auto mutex_send_stats = TSMutexCreate();
    TSCont cb_send_stats  = TSContCreate(send_stats, mutex_send_stats);
    // explicitly set continuation to be null
    // this will force rotation
    TSContDataSet(cb_send_stats, nullptr);

    TSContScheduleEveryOnPool(cb_send_stats, stats_timeout * 1000, TSThreadPool::TS_THREAD_POOL_TASK);

    send_stats_callback = [mutex_send_stats](int offset, int length) {
      // we create a new continuation here because we use the continuation data
      // to relay what needs to be sent
      TSCont cb_send_stats_direct = TSContCreate(send_stats, mutex_send_stats);
      // explicitly set continuation, with the data offset and length to be used
      TSContDataSet(cb_send_stats_direct,
                    reinterpret_cast<void *>(static_cast<uint64_t>(offset) << 32 | static_cast<uint64_t>(length)));
      TSContScheduleOnPool(cb_send_stats_direct, 1, TSThreadPool::TS_THREAD_POOL_TASK);
    };

    TSCont cb_filter_load = TSContCreate(filter_load, nullptr);
    TSLifecycleHookAdd(TSLifecycleHookID::TS_LIFECYCLE_MSG_HOOK, cb_filter_load);
    TSLifecycleHookAdd(TSLifecycleHookID::TS_LIFECYCLE_PORTS_INITIALIZED_HOOK, cb_filter_load);
    // this hook will rotate the data and send it before shutting down
    TSLifecycleHookAdd(TSLifecycleHookID::TS_LIFECYCLE_SHUTDOWN_HOOK, cb_send_stats);
    register_arg_indices();
    Dbg(dbg_ctl, "Index is %d", L7PolicyIndex);
  }
  return;
}
