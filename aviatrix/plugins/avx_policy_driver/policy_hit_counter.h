// hit counter manager
// naive locked increment implementation, under the web_filter's lock we move
// to a new span of memory periodically and when the counter configuration changes
//
// possible optimizations:
// - move to a TLS based counters, we can increment and read without lock, aiming for
//   eventual consistency
// - assign dynamic offsets and retire old counters, to keep memory usage low and prevent
//   overrunning counters not sent yet
// - move to a single counter with an added type of counter as hit an watch are
//   mutually exclusive in this implementation (we move to next block of memory
//   periodically and on counter config change, a counter instance in a span of
//   memory will not receive hit and hit_watch at the same time) this will almost
//   half the memory needed
//
// issues:
// - if we get a lot of configuration changes with large number of policies
//   in a very short period of time we might lag in sending the policies
//   and cause an overrun of old counters
// - locked increment of the counters is an extra shared lock

#pragma once
#include <atomic>
#include <thread>
#include <shared_mutex>

struct policy_hit_counter {
  // UUID, mirroring the proto_buf naming
  uint64_t id_a;
  uint64_t id_b;
  // number of hits
  uint64_t hit;
  // number of hits on watch
  uint64_t hit_watch;
};

const int hit_counter_array_size = 200000;

// todo, move to thread_local storage to stop locking
// make use of alignas for safe access and do deltas on
// the totals to get to a eventual consistent correct count
// challenges:

class PolicyHitCounterManager
{
  policy_hit_counter *_hit_counters;
  uint32_t _current_offset, _current_length;
  mutable std::shared_mutex mutex;

public:
  PolicyHitCounterManager()
  {
    // allocate counters
    _hit_counters   = new policy_hit_counter[hit_counter_array_size];
    _current_offset = 0;
    _current_length = 0;
  }
  ~PolicyHitCounterManager() { delete[] _hit_counters; }
  uint64_t
  Hit(uint32_t index)
  {
    if (index >= _current_length) {
      return 0;
    } else {
      return __atomic_add_fetch(&(_hit_counters[_current_offset + index].hit), 1, static_cast<int>(std::memory_order_relaxed));
      /*std::atomic<uint64_t> &counter = *reinterpret_cast<std::atomic<uint64_t> *>(&(_hit_counters[_current_offset + index].hit));
      return counter.fetch_add(1, std::memory_order_relaxed);*/
    }
  }
  uint64_t
  HitWatch(uint32_t index)
  {
    if (index >= _current_length) {
      return 0;
    }
    return __atomic_add_fetch(&(_hit_counters[_current_offset + index].hit_watch), 1, static_cast<int>(std::memory_order_relaxed));
    /*std::atomic<uint64_t> &counter =
      *reinterpret_cast<std::atomic<uint64_t> *>(&(_hit_counters[_current_offset + index].hit_watch));
    return counter.fetch_add(1, std::memory_order_relaxed);*/
  }

  const policy_hit_counter &
  GetAbsoluteCounter(uint32_t index)
  {
    return _hit_counters[index];
  }

  // move offset to next stretch of memory with
  // zeroed counters, returns false if there was nothing in the old stretch
  // and nothing to process
  bool
  CreateNew(uint32_t new_length)
  {
    if (new_length > GetMaxSize()) {
      new_length = 0;
    }
    bool anyvalue = false;
    for (uint32_t c = 0; c < _current_length; c++) {
      anyvalue = ((_hit_counters[_current_offset + c].hit != 0) || (_hit_counters[_current_offset + c].hit_watch != 0));
      if (anyvalue)
        break;
    }

    uint32_t new_offset = _current_offset + (anyvalue ? _current_length : 0);
    if ((new_offset + new_length) > hit_counter_array_size) {
      new_offset = 0;
    }
    _current_offset = new_offset;
    _current_length = new_length;
    return anyvalue;
  }

  uint32_t
  GetMaxSize()
  {
    return hit_counter_array_size >> 2;
  }

  uint32_t
  CurrentOffset()
  {
    return _current_offset;
  }
  uint32_t
  CurrentLength()
  {
    return _current_length;
  }

  bool
  ResetCounter(uint32_t index, uint64_t id_a, uint64_t id_b)
  {
    if (index >= _current_length) {
      return false;
    } else {
      _hit_counters[_current_offset + index] = {id_a, id_b, 0, 0};
      return true;
    }
  }

  // copies current counter ids (a,b) to next stretch of memory with
  // zeroed counters, returns false if there was nothing to copy and to
  // process
  bool
  CopyNext()
  {
    auto new_offset = _current_offset + _current_length;
    // only allow for continuous stretches
    if ((new_offset + _current_length) > hit_counter_array_size) {
      new_offset = 0;
    }
    bool anyvalue = false;
    for (uint32_t c = 0; c < _current_length; c++) {
      _hit_counters[new_offset + c]            = _hit_counters[_current_offset + c];
      _hit_counters[new_offset + c].hit        = 0;
      _hit_counters[new_offset + c].hit_watch  = 0;
      anyvalue                                |= (_hit_counters[_current_offset + c].hit != 0);
      anyvalue                                |= (_hit_counters[_current_offset + c].hit_watch != 0);
    }
    // do not move to next stretch if no changes
    if (!anyvalue)
      return false;

    _current_offset = new_offset;
    return true;
  }
};
