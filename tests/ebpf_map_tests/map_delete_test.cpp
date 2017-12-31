#include <gtest/gtest.h>

extern "C" {
#include <stdint.h>
#include <errno.h>
#include <assert.h>
#include <dev/ebpf/ebpf_map.h>
}

namespace {
class MapDeleteTest : public ::testing::Test {
protected:
  struct ebpf_map map;

  virtual void SetUp() {
    int error;

    error = ebpf_map_init(&map, EBPF_MAP_TYPE_ARRAY,
        sizeof(uint32_t), sizeof(uint32_t), 100, 0);
    assert(!error);
  }

  virtual void TearDown() {
    ebpf_map_deinit(&map, NULL);
  }
};

TEST_F(MapDeleteTest, DeleteWithNULLMap) {
  int error;
  uint32_t key = 100;

  error = ebpf_map_delete_elem(NULL, &key);

  EXPECT_EQ(EINVAL, error);
}

TEST_F(MapDeleteTest, DeleteWithNULLKey) {
  int error;

  error = ebpf_map_delete_elem(&map, NULL);

  EXPECT_EQ(EINVAL, error);
}
}
