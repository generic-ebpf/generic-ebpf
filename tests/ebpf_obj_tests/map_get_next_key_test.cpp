#include <gtest/gtest.h>

extern "C" {
#include <stdint.h>
#include <errno.h>
#include <assert.h>
#include <dev/ebpf/ebpf_map.h>
}

namespace {
class MapGetNextKeyTest : public ::testing::Test {
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

TEST_F(MapGetNextKeyTest, GetNextKeyWithNULLMap) {
  int error;
  uint32_t key = 50, next_key;

  error = ebpf_map_get_next_key(NULL, &key, &next_key);

  EXPECT_EQ(EINVAL, error);
}

TEST_F(MapGetNextKeyTest, GetNextKeyWithNULLKey) {
  int error;
  uint32_t key = 50, next_key;

  error = ebpf_map_get_next_key(map, NULL, &next_key);

  EXPECT_NE(EINVAL, error);
}

TEST_F(MapGetNextKeyTest, GetNextKeyWithNULLNextKey) {
  int error;
  uint32_t key = 50;

  error = ebpf_map_get_next_key(map, &key, NULL);

  EXPECT_EQ(EINVAL, error);
}
}
