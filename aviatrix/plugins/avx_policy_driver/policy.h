/*
 * Definitions about the policy framework
 */
#ifndef _POLICY_H
#define _POLICY_H

#include "proto/common/types.pb.h"
#include "web_filter.h"
#include "ts/ts.h"

extern const char *L7PolicyTag;
extern int L7PolicyIndex;

enum PolicyResult {
  POLICY_INIT,
  POLICY_PERMIT,
  POLICY_DROP,
  POLICY_IDS,
  POLICY_CONTINUE,
  POLICY_ERROR,
  POLICY_END,
};

union PolicyEvalInfo {
  struct {
    uint16_t initialized;
    int16_t watched;
    uint16_t generation;
    int16_t offset;
  } fields;
  uint64_t value;
};

bool do_filter(void *policy, const char *server_name);
bool has_ids(void *policy);
bool IsPolicyLoaded();
bool LoadPolicy(bool skip_if_exists);
PolicyResult EvaluatePolicySni(TSVConn vconn, uint64_t *policy_offset);
PolicyResult EvaluatePolicyTxn(TSHttpTxn, uint64_t *policy_offset);

void RotatePolicyHitCounters();
bool SendPolicyHitCounters(int offset, int length);

#endif
