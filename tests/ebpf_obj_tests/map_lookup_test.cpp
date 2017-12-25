#include <gtest/gtest.h>

extern "C" {
#include <stdint.h>
#include <errno.h>
#include <assert.h>
#include <dev/ebpf/ebpf_map.h>
}

namespace {
class MapLookupTest : public ::testing::Test {
protected:
  struct ebpf_obj_map *map;

  virtual void SetUp() {
    int error;

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
  }

  virtual void TearDown() {
    ebpf_obj_delete((struct ebpf_obj *)map);
  }
};

TEST_F(MapLookupTest, LookupWithNULLMap) {
  int error;
  uint32_t key = 50;
  void *value;

  value = ebpf_map_lookup_elem(NULL, (void *)&key, 0);

  EXPECT_EQ(NULL, value);
}

TEST_F(MapLookupTest, LookupWithNULLKey) {
  int error;
  void *value;

  value = ebpf_map_lookup_elem(map, NULL, 0);

  EXPECT_EQ(NULL, value);
}

TEST_F(MapLookupTest, LookupWithNULLValue) {
  int error;
  uint32_t key = 100;
  void *value;

  value = ebpf_map_lookup_elem(map, (void *)&key, 0);

  EXPECT_EQ(NULL, value);
}
}
