#include <gtest/gtest.h>

extern "C" {
#include <stdint.h>
#include <errno.h>
#include <assert.h>
#include <dev/ebpf/ebpf_map.h>
}

namespace {
class ArrayMapUpdateTest : public ::testing::Test {
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

TEST_F(ArrayMapUpdateTest, UpdateWithMaxPlusOneKey) {
  int error;
  uint32_t key = 100, value = 100;

  error = ebpf_map_update_elem(map, &key, &value, 0);

  EXPECT_EQ(EINVAL, error);
}

TEST_F(ArrayMapUpdateTest, CorrectUpdate) {
  int error;
  uint32_t key = 50, value = 100;

  error = ebpf_map_update_elem(map, &key, &value, 0);

  EXPECT_EQ(0, error);
}
}
