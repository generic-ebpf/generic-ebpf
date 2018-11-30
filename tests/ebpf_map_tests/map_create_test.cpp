#include <gtest/gtest.h>

extern "C" {
#include <stdint.h>
#include <errno.h>
#include <dev/ebpf/ebpf_map.h>
}

TEST(MapCreateTest, CreateWithNULLMapPointer)
{
	int error;

	error = ebpf_map_init(NULL, EBPF_MAP_TYPE_ARRAY, sizeof(uint32_t),
			      sizeof(uint32_t), 100, 0);

	EXPECT_EQ(EINVAL, error);
}

TEST(MapCreateTest, CreateWithInvalidMapType1)
{
	int error;
	struct ebpf_map map;

	error = ebpf_map_init(&map, EBPF_MAP_TYPE_MAX, sizeof(uint32_t),
			      sizeof(uint32_t), 100, 0);

	EXPECT_EQ(EINVAL, error);
}

TEST(MapCreateTest, CreateWithInvalidMapType2)
{
	int error;
	struct ebpf_map map;

	error = ebpf_map_init(&map, EBPF_MAP_TYPE_MAX + 1, sizeof(uint32_t),
			      sizeof(uint32_t), 100, 0);

	EXPECT_EQ(EINVAL, error);
}

TEST(MapCreateTest, CreateWithZeroKey)
{
	int error;
	struct ebpf_map map;

	error = ebpf_map_init(&map, EBPF_MAP_TYPE_ARRAY, 0, sizeof(uint32_t),
			      100, 0);

	EXPECT_EQ(EINVAL, error);
}

TEST(MapCreateTest, CreateWithZeroValue)
{
	int error;
	struct ebpf_map map;

	error = ebpf_map_init(&map, EBPF_MAP_TYPE_ARRAY, sizeof(uint32_t), 0,
			      100, 0);

	EXPECT_EQ(EINVAL, error);
}

TEST(MapCreateTest, CreateWithZeroMaxEntries)
{
	int error;
	struct ebpf_map map;

	error = ebpf_map_init(&map, EBPF_MAP_TYPE_ARRAY, sizeof(uint32_t), 0,
			      100, 0);

	EXPECT_EQ(EINVAL, error);
}
