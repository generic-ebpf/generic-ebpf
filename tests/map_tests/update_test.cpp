#include <gtest/gtest.h>

extern "C" {
#include <stdint.h>
#include <errno.h>
#include <assert.h>
#include <dev/ebpf/ebpf_map.h>
}

namespace {
class MapUpdateTest : public ::testing::Test {
protected:
  struct ebpf_obj_map *map;

  virtual void SetUp() {
    int error;

    union ebpf_req req = {
      .map_fdp = NULL,
      .map_type = EBPF_MAP_TYPE_ARRAY,
      .key_size = sizeof(uint32_t),
      .value_size = sizeof(uint32_t),
      .max_entries = 100,
      .map_flags = 0
    };

    error = ebpf_obj_new((struct ebpf_obj **)&map,
        EBPF_OBJ_TYPE_MAP, &req);

    assert(!error);
  }

  virtual void TearDown() {
    ebpf_obj_delete((struct ebpf_obj *)map);
  }
};

TEST_F(MapUpdateTest, UpdateWithNULLMap) {
  int error;
  uint32_t key = 50, value = 100;

  error = ebpf_map_update_elem(NULL, &key, &value, 0);

  EXPECT_EQ(EINVAL, error);
}

TEST_F(MapUpdateTest, UpdateWithNULLKey) {
  int error;
  uint32_t value = 100;

  error = ebpf_map_update_elem(map, NULL, &value, 0);

  EXPECT_EQ(EINVAL, error);
}

TEST_F(MapUpdateTest, UpdateWithNULLValue) {
  int error;
  uint32_t key = 100;

  error = ebpf_map_update_elem(map, &key, NULL, 0);

  EXPECT_EQ(EINVAL, error);
}
}
