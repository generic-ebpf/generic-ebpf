#include <gtest/gtest.h>

extern "C" {
#include <stdint.h>
#include <errno.h>
#include <dev/ebpf/ebpf_map.h>
}

TEST(MapCreateTest, CreateWithNULLMapPointer)
{
  int error;
  struct ebpf_obj_map *map;

  union ebpf_req req = {
    .map_fdp = NULL,
    .map_type = EBPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(uint32_t),
    .max_entries = 0,
    .map_flags = 0
  };

  error = ebpf_obj_new(NULL, EBPF_OBJ_TYPE_MAP, &req);

  EXPECT_EQ(EINVAL, error);
}

TEST(MapCreateTest, CreateWithNULLReq)
{
  int error;
  struct ebpf_obj_map *map;

  error = ebpf_obj_new((struct ebpf_obj **)&map, EBPF_OBJ_TYPE_MAP, NULL);

  EXPECT_EQ(EINVAL, error);
}

TEST(MapCreateTest, CreateWithInvalidMapType1)
{
  int error;
  struct ebpf_obj_map *map;

  union ebpf_req req = {
    .map_fdp = NULL,
    .map_type = __EBPF_MAP_TYPE_MAX,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(uint32_t),
    .max_entries = 0,
    .map_flags = 0
  };

  error = ebpf_obj_new((struct ebpf_obj **)&map, EBPF_OBJ_TYPE_MAP, &req);

  EXPECT_EQ(EINVAL, error);
}

TEST(MapCreateTest, CreateWithInvalidMapType2)
{
  int error;
  struct ebpf_obj_map *map;

  union ebpf_req req = {
    .map_fdp = NULL,
    .map_type = __EBPF_MAP_TYPE_MAX + 1,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(uint32_t),
    .max_entries = 0,
    .map_flags = 0
  };

  error = ebpf_obj_new((struct ebpf_obj **)&map, EBPF_OBJ_TYPE_MAP, &req);

  EXPECT_EQ(EINVAL, error);
}

TEST(MapCreateTest, CreateWithZeroKey)
{
  int error;
  struct ebpf_obj_map *map;

  union ebpf_req req = {
    .map_fdp = NULL,
    .map_type = EBPF_MAP_TYPE_ARRAY,
    .key_size = 0,
    .value_size = sizeof(uint32_t),
    .max_entries = 100,
    .map_flags = 0
  };

  error = ebpf_obj_new((struct ebpf_obj **)&map, EBPF_OBJ_TYPE_MAP, &req);

  EXPECT_EQ(EINVAL, error);
}

TEST(MapCreateTest, CreateWithZeroValue)
{
  int error;
  struct ebpf_obj_map *map;

  union ebpf_req req = {
    .map_fdp = NULL,
    .map_type = EBPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(uint32_t),
    .value_size = 0,
    .max_entries = 100,
    .map_flags = 0
  };

  error = ebpf_obj_new((struct ebpf_obj **)&map, EBPF_OBJ_TYPE_MAP, &req);

  EXPECT_EQ(EINVAL, error);
}

TEST(MapCreateTest, CreateWithZeroMaxEntries)
{
  int error;
  struct ebpf_obj_map *map;

  union ebpf_req req = {
    .map_fdp = NULL,
    .map_type = EBPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(uint32_t),
    .max_entries = 0,
    .map_flags = 0
  };

  error = ebpf_obj_new((struct ebpf_obj **)&map, EBPF_OBJ_TYPE_MAP, &req);

  EXPECT_EQ(EINVAL, error);
}
