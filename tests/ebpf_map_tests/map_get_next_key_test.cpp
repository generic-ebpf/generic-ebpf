#include <gtest/gtest.h>

extern "C" {
#include <stdint.h>
#include <errno.h>

#include <dev/ebpf/ebpf_map.h>
}

namespace {
class MapGetNextKeyTest : public ::testing::Test {
      protected:
	struct ebpf_obj_map *eom;

	virtual void
	SetUp()
	{
		int error;

		struct ebpf_map_attr attr;
		attr.type = EBPF_MAP_TYPE_ARRAY;
		attr.key_size = sizeof(uint32_t);
		attr.value_size = sizeof(uint32_t);
		attr.max_entries = 100;
		attr.flags = 0;

		error = ebpf_map_create(&eom, &attr);
		ASSERT_TRUE(!error);
	}

	virtual void
	TearDown()
	{
		ebpf_map_destroy(eom);
	}
};

TEST_F(MapGetNextKeyTest, GetNextKeyWithNULLMap)
{
	int error;
	uint32_t key = 50, next_key = 0;

	error = ebpf_map_get_next_key_from_user(NULL, &key, &next_key);

	EXPECT_EQ(EINVAL, error);
}

TEST_F(MapGetNextKeyTest, GetNextKeyWithNULLKey)
{
	int error;
	uint32_t key = 50, next_key = 0;

	error = ebpf_map_get_next_key_from_user(eom, NULL, &next_key);

	EXPECT_NE(EINVAL, error);
}

TEST_F(MapGetNextKeyTest, GetNextKeyWithNULLNextKey)
{
	int error;
	uint32_t key = 50;

	error = ebpf_map_get_next_key_from_user(eom, &key, NULL);

	EXPECT_EQ(EINVAL, error);
}
} // namespace
