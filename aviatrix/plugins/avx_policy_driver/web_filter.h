#include <string>
#include <unordered_map>
#include <swoc/swoc_ip.h>

#ifndef _WEB_FILTER_H
#define _WEB_FILTER_H
#include "proto/conduit/v2/layer7.pb.h"
#include "proto/conduit/v2/microseg.pb.h"
#include "proto/common/types.pb.h"

using namespace proto::common;

Layer7Config *FetchLayer7Policy();
const HitCounterResult *SendLayer7PolicyHitCounters(HitCounters &hit_counters);

enum MatchResult { MatchValues, NotMatchValues, NoRuleToMatch, NoAttributeToMatch };

// A hash function used to hash a UUID
struct hash_uuid {
  uint64_t
  operator()(const std::pair<const uint64_t, const uint64_t> &uuid) const
  {
    return uuid.first ^ uuid.second;
  }
};
/*
 * Data structures to encoding string matches for web filtering
 */
class WebFilterImpl
{
public:
  WebFilterImpl(WebFilter &);
  enum FilterType { SniFilter, UrlFilter };
  FilterType type = SniFilter;
  bool match_all  = false;
  MatchResult match(std::string_view sni_input, std::string_view url_input);

private:
  std::string name;
  std::unordered_map<std::string, bool> complete_match;
  std::unordered_map<std::string, bool> suffix_partial_match;
  std::unordered_map<std::string, bool> prefix_partial_match;
};

class WebFilters
{
public:
  MatchResult match(UUID &uuid, std::string_view sni_input, std::string_view url_input);
  bool load(Layer7Config &config);

private:
  // Keyed by uuid
  std::unordered_map<std::pair<uint64_t, uint64_t>, WebFilterImpl *, hash_uuid> web_filter_map;
};

class TrafficFilterImpl
{
public:
  TrafficFilterImpl(MicrosegTrafficFilter &tf);
  MatchResult match(const struct sockaddr_in *);

private:
  std::string name;
  swoc::IPSpace<bool> lookup_map;
};

class TrafficFilters
{
public:
  MatchResult match(UUID &uuid, struct sockaddr_in *);
  bool load(Layer7Config &config);

private:
  // keyed by uuid
  std::unordered_map<std::pair<uint64_t, uint64_t>, TrafficFilterImpl *, hash_uuid> traffic_filter_map;
};

extern std::function<void(int, int)> send_stats_callback;
#endif
