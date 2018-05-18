#include <gtest/gtest.h>

extern "C" {
#include <stdint.h>
#include <errno.h>

#include <dev/ebpf/ebpf_map.h>
}

namespace {
class MapUpdateTest : public ::testing::Test {
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

TEST_F(MapUpdateTest, UpdateWithNULLMap)
{
	int error;
	uint32_t key = 50, value = 100;

	error = ebpf_map_update_elem(NULL, &key, &value, EBPF_ANY);

	EXPECT_EQ(EINVAL, error);
}

TEST_F(MapUpdateTest, UpdateWithNULLKey)
{
	int error;
	uint32_t value = 100;

	error = ebpf_map_update_elem(&map, NULL, &value, EBPF_ANY);

	EXPECT_EQ(EINVAL, error);
}

TEST_F(MapUpdateTest, UpdateWithNULLValue)
{
	int error;
	uint32_t key = 100;

	error = ebpf_map_update_elem(&map, &key, NULL, EBPF_ANY);

	EXPECT_EQ(EINVAL, error);
}

TEST_F(MapUpdateTest, UpdateWithInvalidFlag)
{
	int error;
	uint32_t key = 1, value = 1;

	error = ebpf_map_update_elem(&map, &key, &value, EBPF_EXIST + 1);

	EXPECT_EQ(EINVAL, error);
}
}
