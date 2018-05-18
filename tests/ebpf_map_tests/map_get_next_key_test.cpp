#include <gtest/gtest.h>

extern "C" {
#include <stdint.h>
#include <errno.h>

#include <dev/ebpf/ebpf_map.h>
}

namespace {
class MapGetNextKeyTest : public ::testing::Test {
      protected:
	struct ebpf_map map;

	virtual void
	SetUp()
	{
		int error;

		error =
		    ebpf_map_init(&map, EBPF_MAP_TYPE_ARRAY, sizeof(uint32_t),
				  sizeof(uint32_t), 100, 0);
		ASSERT_TRUE(!error);
	}

	virtual void
	TearDown()
	{
		ebpf_map_deinit(&map, NULL);
	}
};

TEST_F(MapGetNextKeyTest, GetNextKeyWithNULLMap)
{
	int error;
	uint32_t key = 50, next_key = 0;

	error = ebpf_map_get_next_key(NULL, &key, &next_key);

	EXPECT_EQ(EINVAL, error);
}

TEST_F(MapGetNextKeyTest, GetNextKeyWithNULLKey)
{
	int error;
	uint32_t key = 50, next_key = 0;

	error = ebpf_map_get_next_key(&map, NULL, &next_key);

	EXPECT_NE(EINVAL, error);
}

TEST_F(MapGetNextKeyTest, GetNextKeyWithNULLNextKey)
{
	int error;
	uint32_t key = 50;

	error = ebpf_map_get_next_key(&map, &key, NULL);

	EXPECT_EQ(EINVAL, error);
}
}
