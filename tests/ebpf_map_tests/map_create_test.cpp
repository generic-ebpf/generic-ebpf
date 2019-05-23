#include <gtest/gtest.h>

extern "C" {
#include <stdint.h>
#include <errno.h>
#include <dev/ebpf/ebpf_map.h>
}

TEST(MapCreateTest, CreateWithNULLMapPointer)
{
	int error;

	struct ebpf_map_attr attr;
	attr.type = EBPF_MAP_TYPE_ARRAY;
	attr.key_size = sizeof(uint32_t);
	attr.value_size = sizeof(uint32_t);
	attr.max_entries = 100;
	attr.flags = 0;

	error = ebpf_map_create(NULL, &attr);

	EXPECT_EQ(EINVAL, error);
}

TEST(MapCreateTest, CreateWithInvalidMapType1)
{
	int error;
	struct ebpf_obj_map *eom;

	struct ebpf_map_attr attr;
	attr.type = EBPF_MAP_TYPE_MAX;
	attr.key_size = sizeof(uint32_t);
	attr.value_size = sizeof(uint32_t);
	attr.max_entries = 100;
	attr.flags = 0;

	error = ebpf_map_create(&eom, &attr);

	EXPECT_EQ(EINVAL, error);
}

TEST(MapCreateTest, CreateWithInvalidMapType2)
{
	int error;
	struct ebpf_obj_map *eom;

	struct ebpf_map_attr attr;
	attr.type = EBPF_MAP_TYPE_MAX + 1;
	attr.key_size = sizeof(uint32_t);
	attr.value_size = sizeof(uint32_t);
	attr.max_entries = 100;
	attr.flags = 0;

	error = ebpf_map_create(&eom, &attr);

	EXPECT_EQ(EINVAL, error);
}

TEST(MapCreateTest, CreateWithZeroKey)
{
	int error;
	struct ebpf_obj_map *eom;

	struct ebpf_map_attr attr;
	attr.type = EBPF_MAP_TYPE_ARRAY;
	attr.key_size = 0;
	attr.value_size = sizeof(uint32_t);
	attr.max_entries = 100;
	attr.flags = 0;

	error = ebpf_map_create(&eom, &attr);

	EXPECT_EQ(EINVAL, error);
}

TEST(MapCreateTest, CreateWithZeroValue)
{
	int error;
	struct ebpf_obj_map *eom;

	struct ebpf_map_attr attr;
	attr.type = EBPF_MAP_TYPE_ARRAY;
	attr.key_size = sizeof(uint32_t);
	attr.value_size = 0;
	attr.max_entries = 100;
	attr.flags = 0;

	error = ebpf_map_create(&eom, &attr);

	EXPECT_EQ(EINVAL, error);
}

TEST(MapCreateTest, CreateWithZeroMaxEntries)
{
	int error;
	struct ebpf_obj_map *eom;

	struct ebpf_map_attr attr;
	attr.type = EBPF_MAP_TYPE_ARRAY;
	attr.key_size = sizeof(uint32_t);
	attr.value_size = sizeof(uint32_t);
	attr.max_entries = 0;
	attr.flags = 0;

	error = ebpf_map_create(&eom, &attr);

	EXPECT_EQ(EINVAL, error);
}
