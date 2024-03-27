#include <stdlib.h>
#include <string>
#define CATCH_CONFIG_MAIN
#include "policy_hit_counter.h"
#include <catch.hpp>

class TestCase
{
public:
  std::string testInput;
  bool expectedResult;
};

TEST_CASE("Initial should be empty", "[Hitcounter]")
{
  PolicyHitCounterManager pm;
  REQUIRE(pm.CurrentLength() == 0);
  REQUIRE(pm.CurrentOffset() == 0);
}

TEST_CASE("createnew boundaries", "[Hitcounter]")
{
  PolicyHitCounterManager pm;
  REQUIRE(pm.CurrentLength() == 0);
  REQUIRE(pm.CurrentOffset() == 0);

  SECTION("Out of bounds should yield length 0")
  {
    pm.CreateNew(-1);
    REQUIRE(pm.CurrentLength() == 0);
    REQUIRE(pm.CurrentOffset() == 0);

    pm.CreateNew(pm.GetMaxSize() + 1);
    REQUIRE(pm.CurrentLength() == 0);
    REQUIRE(pm.CurrentOffset() == 0);
  }
  SECTION("Valid length should return creation length")
  {
    pm.CreateNew(0);
    REQUIRE(pm.CurrentLength() == 0);
    REQUIRE(pm.CurrentOffset() == 0);

    pm.CreateNew(2000);
    REQUIRE(pm.CurrentLength() == 2000);
    REQUIRE(pm.CurrentOffset() == 0);

    pm.CreateNew(pm.GetMaxSize());
    REQUIRE(pm.CurrentLength() == pm.GetMaxSize());
    REQUIRE(pm.CurrentOffset() == 0);
  }
}

TEST_CASE("Empty runs should not move forward in the buffer", "[HitCounter]")
{
  auto run = [](int size) -> void {

  };
  uint32_t sizes[] = {0, 1, 2000};
  for (auto size : sizes) {
    DYNAMIC_SECTION("Run " << size)
    {
      PolicyHitCounterManager pm;
      REQUIRE(pm.CurrentLength() == 0);
      auto movenext = pm.CreateNew(size);
      REQUIRE(movenext == false);
      movenext = pm.CopyNext();
      REQUIRE(movenext == false);
      REQUIRE(pm.CurrentLength() == size);
      REQUIRE(pm.CurrentOffset() == 0);
    }
  }
}

TEST_CASE("A hit or hit_watch should move the buffer forward with CopyNext and CreateNext", "[HitCounter]")
{
  PolicyHitCounterManager pm;
  REQUIRE(pm.CurrentLength() == 0);
  pm.CreateNew(2000);
  for (uint32_t c = 0; c < 2000; c++)
    pm.ResetCounter(c, c + 1, c + 2);
  pm.Hit(1);
  auto movenext = pm.CopyNext();
  REQUIRE(movenext == true);
  REQUIRE(pm.CurrentLength() == 2000);
  REQUIRE(pm.CurrentOffset() == 2000);

  pm.HitWatch(1);
  movenext = pm.CopyNext();
  REQUIRE(movenext == true);
  REQUIRE(pm.CurrentLength() == 2000);
  REQUIRE(pm.CurrentOffset() == 4000);
  pm.Hit(1);
  movenext = pm.CreateNew(2000);
  REQUIRE(movenext == true);

  for (uint32_t c = 0; c < 2000; c++)
    pm.ResetCounter(c, c + 1, c + 2);

  REQUIRE(pm.CurrentLength() == 2000);
  REQUIRE(pm.CurrentOffset() == 6000);
  pm.HitWatch(1);
  movenext = pm.CreateNew(2000);
  REQUIRE(movenext == true);
  for (uint32_t c = 0; c < 2000; c++)
    pm.ResetCounter(c, c + 1, c + 2);

  REQUIRE(pm.CurrentLength() == 2000);
  REQUIRE(pm.CurrentOffset() == 8000);
}

TEST_CASE("Copynext should preserve the ids ", "[HitCounter]")
{
  PolicyHitCounterManager pm;
  REQUIRE(pm.CurrentLength() == 0);
  pm.CreateNew(2000);
  for (uint32_t c = 0; c < 2000; c++) {
    pm.ResetCounter(c, c + 1, c + 2);
  }
  auto movenext = pm.CopyNext();
  REQUIRE(movenext == false);
  REQUIRE(pm.CurrentLength() == 2000);
  REQUIRE(pm.CurrentOffset() == 0);

  for (uint32_t c = 0; c < 2000; c++) {
    auto pc = pm.GetAbsoluteCounter(c);
    REQUIRE(((pc.id_a == c + 1) && (pc.id_b == c + 2)));
  }

  pm.HitWatch(1);
  movenext = pm.CopyNext();
  REQUIRE(movenext == true);
  REQUIRE(pm.CurrentLength() == 2000);
  REQUIRE(pm.CurrentOffset() == 2000);

  for (uint32_t c = 0; c < 2000; c++) {
    auto pc = pm.GetAbsoluteCounter(c + pm.CurrentOffset());
    REQUIRE((pc.id_a == c + 1 && pc.id_b == c + 2));
  }
}

TEST_CASE("hit and hitwatch should count correctly and reset to 0 with copynext ", "[HitCounter]")
{
  PolicyHitCounterManager pm;
  REQUIRE(pm.CurrentLength() == 0);
  pm.CreateNew(2000);
  for (uint32_t c = 0; c < 2000; c++) {
    pm.ResetCounter(c, c + 1, c + 2);
  }

  for (int c = 0; c < 2000; c++) {
    for (uint32_t d = 0; d <= c; d++) {
      pm.Hit(d);
      pm.HitWatch(1999 - d);
    }
  }
  auto movenext = pm.CopyNext();
  REQUIRE(movenext == true);
  REQUIRE(pm.CurrentLength() == 2000);
  REQUIRE(pm.CurrentOffset() == 2000);

  for (uint32_t c = 0; c < 2000; c++) {
    auto pc = pm.GetAbsoluteCounter(c);
    REQUIRE(pc.id_a == c + 1);
    REQUIRE(pc.id_b == c + 2);
    REQUIRE(pc.hit == 2000 - c);
    REQUIRE(pc.hit_watch == c + 1);
  }
  // counter id's should be carried over and hit/hit_watch should be 0
  for (uint32_t c = 0; c < 2000; c++) {
    auto pc = pm.GetAbsoluteCounter(c + pm.CurrentOffset());
    REQUIRE((pc.id_a == c + 1 && pc.id_b == c + 2));
    REQUIRE(((pc.hit == 0)));
    REQUIRE(((pc.hit_watch == 0)));
  }
}

TEST_CASE("moving to the next buffer we should wrap around correctly ", "[HitCounter]")
{
  PolicyHitCounterManager pm;
  int n    = hit_counter_array_size / 768;
  int rest = hit_counter_array_size % 768;
  for (uint32_t c = 0; c < n; c++) {
    pm.CreateNew(768);
    REQUIRE(pm.CurrentOffset() == c * 768);
    pm.ResetCounter(0, 1, 2);
    pm.Hit(0);
  }
  pm.Hit(1);
  SECTION("Wrap around exactly at boundary")
  {
    pm.CreateNew(rest);
    REQUIRE(pm.CurrentOffset() == hit_counter_array_size - rest);
    pm.ResetCounter(0, 1, 2);
    pm.Hit(1);
    pm.CreateNew(768);
    REQUIRE(pm.CurrentOffset() == 0);
  };
  SECTION("Wrap around at boundary + 1 ")
  {
    pm.CreateNew(rest + 1);
    REQUIRE(pm.CurrentOffset() == 0);
  };
}
