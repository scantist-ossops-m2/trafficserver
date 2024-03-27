#pragma once
#include <atomic>
#include <netinet/in.h>
#include <time.h>

enum policy_log_prio { log_emerg, log_alert, log_crit, log_err, log_warning, log_notice, log_info, log_debug };
struct policy_log_message {
  policy_log_prio priority;
  const char *action;
  const char *reason;
  struct sockaddr_in *src;
  struct sockaddr_in *dest;
  bool enforced;
  int connection_id;
  int txn_id;
  const char *errorcode;
  const char *stage;
  const char *message;
  const char *sni_hostname;
  const char *decided_by;
  const char *decrypted_by;
  const char *url;
  bool decision;
  bool ids;
  time_t timestamp;
};

void policy_log(policy_log_message &msg);

bool sprint_uuid(char *buf, uint64_t a, uint64_t b);
