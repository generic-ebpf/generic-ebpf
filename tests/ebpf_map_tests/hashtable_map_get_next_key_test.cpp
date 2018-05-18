#include <gtest/gtest.h>

extern "C" {
#include <stdint.h>
#include <errno.h>

#include <dev/ebpf/ebpf_map.h>
}

namespace {
class HashTableMapGetNextKeyTest : public ::testing::Test {
      protected:
	struct ebpf_map map;

	virtual void
	SetUp()
	{
		int error;
		uint32_t gkey1 = 50;
		uint32_t gval1 = 100;
		uint32_t gkey2 = 70;
		uint32_t gval2 = 120;

		error =
		    ebpf_map_init(&map, EBPF_MAP_TYPE_HASHTABLE,
				  sizeof(uint32_t), sizeof(uint32_t), 100, 0);
		ASSERT_TRUE(!error);

		error = ebpf_map_update_elem(&map, &gkey1, &gval1, 0);
		ASSERT_TRUE(!error);
		error = ebpf_map_update_elem(&map, &gkey2, &gval2, 0);
		ASSERT_TRUE(!error);
	}

	virtual void
	TearDown()
	{
		ebpf_map_deinit(&map, NULL);
	}
};

TEST_F(HashTableMapGetNextKeyTest, GetFirstKey)
{
	int error;
	uint32_t next_key = 0;

	error = ebpf_map_get_next_key(&map, NULL, &next_key);

	EXPECT_EQ(0, error);
}

TEST_F(HashTableMapGetNextKeyTest, CorrectGetNextKey)
{
	int error;
	uint32_t key = 50, next_key = 0;

	error = ebpf_map_get_next_key(&map, &key, &next_key);

	EXPECT_EQ(70, next_key);
}
}
