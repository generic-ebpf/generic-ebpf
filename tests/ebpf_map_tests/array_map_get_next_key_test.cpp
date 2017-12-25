#include <gtest/gtest.h>

extern "C" {
#include <stdint.h>
#include <errno.h>
#include <assert.h>
#include <dev/ebpf/ebpf_map.h>
}

namespace {
class ArrayMapGetNextKeyTest : public ::testing::Test {
protected:
  struct ebpf_obj_map *map;

  virtual void SetUp() {
    int error;
    uint32_t gkey1 = 50;
    uint32_t gval1 = 100;
    uint32_t gkey2 = 70;
    uint32_t gval2 = 120;

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

    error = ebpf_map_update_elem(map, &gkey1, &gval1, 0);
    assert(!error);
    error = ebpf_map_update_elem(map, &gkey2, &gval2, 0);
    assert(!error);
  }

  virtual void TearDown() {
    ebpf_obj_delete((struct ebpf_obj *)map);
  }
};

TEST_F(ArrayMapGetNextKeyTest, GetNextKeyWithMaxKey) {
  int error;
  uint32_t key = 99, next_key;

  error = ebpf_map_get_next_key(map, &key, &next_key);

  EXPECT_EQ(50, next_key);
}

TEST_F(ArrayMapGetNextKeyTest, GetFirstKey) {
  int error;
  uint32_t next_key;

  error = ebpf_map_get_next_key(map, NULL, &next_key);

  EXPECT_EQ(50, next_key);
}

TEST_F(ArrayMapGetNextKeyTest, CorrectGetNextKey) {
  int error;
  uint32_t key = 50, next_key;

  error = ebpf_map_get_next_key(map, &key, &next_key);

  EXPECT_EQ(70, next_key);
}
}
