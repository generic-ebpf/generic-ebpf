#include <gtest/gtest.h>

extern "C" {
#include <stdint.h>
#include <errno.h>

#include <dev/ebpf/ebpf_map.h>
}

namespace {

class PercpuHashTableMapDeleteTest : public ::testing::Test {
      protected:
	struct ebpf_map map;

	virtual void
	SetUp()
	{
		int error;
		uint32_t gkey = 50;
		uint32_t gval = 100;

		struct ebpf_map_attr attr;
		attr.type = EBPF_MAP_TYPE_PERCPU_HASHTABLE;
		attr.key_size = sizeof(uint32_t);
		attr.value_size = sizeof(uint32_t);
		attr.max_entries = 100;
		attr.flags = 0;

		error = ebpf_map_init(&map, &attr);
		ASSERT_TRUE(!error);

		error = ebpf_map_update_elem_from_user(&map, &gkey, &gval, 0);
		ASSERT_TRUE(!error);
	}

	virtual void
	TearDown()
	{
		ebpf_map_deinit(&map, NULL);
	}
};

TEST_F(PercpuHashTableMapDeleteTest, CorrectDelete)
{
	int error;
	uint32_t key = 50;

	error = ebpf_map_delete_elem_from_user(&map, &key);
	EXPECT_EQ(0, error);
}
} // namespace
