#include <gtest/gtest.h>

extern "C" {
#include <stdint.h>
#include <errno.h>
#include <assert.h>
#include <dev/ebpf/ebpf_map.h>
}

namespace {
class ArrayMapLookupTest : public ::testing::Test {
protected:
  struct ebpf_obj_map *map;

  virtual void SetUp() {
    int error;
    uint32_t gkey = 50, gval = 100;

    union ebpf_req req;
    req.map_fdp = NULL;
    req.map_type = EBPF_MAP_TYPE_ARRAY;
    req.key_size = sizeof(uint32_t);
    req.value_size = sizeof(uint32_t);
    req.max_entries = 100;
    req.map_flags = 0;

    error = ebpf_obj_new((struct ebpf_obj **)&map,
        EBPF_OBJ_TYPE_MAP, &req);
    assert(!error);

    error = ebpf_map_update_elem(map, &gkey, &gval, 0);
    assert(!error);
  }

  virtual void TearDown() {
    ebpf_obj_delete((struct ebpf_obj *)map);
  }
};

TEST_F(ArrayMapLookupTest, LookupUnexistingEntry) {
  int error;
  uint32_t key = 51;
  void *value;

  value = ebpf_map_lookup_elem(map, &key, 0);

  EXPECT_EQ(NULL, value);
}

TEST_F(ArrayMapLookupTest, LookupMaxEntryPlusOne) {
  int error;
  uint32_t key = 100;
  void *value;

  value = ebpf_map_lookup_elem(map, &key, 0);

  EXPECT_EQ(NULL, value);
}

TEST_F(ArrayMapLookupTest, LookupOutOfMaxEntry) {
  int error;
  uint32_t key = 102;
  void *value;

  value = ebpf_map_lookup_elem(map, &key, 0);

  EXPECT_EQ(NULL, value);
}

TEST_F(ArrayMapLookupTest, CorrectLookup) {
  int error;
  uint32_t key = 50;
  uint32_t *value;

  value = (uint32_t *)ebpf_map_lookup_elem(map, &key, 0);

  EXPECT_EQ(100, *value);
}
}
