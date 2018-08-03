#include <gtest/gtest.h>

extern "C" {
#include <stdint.h>
#include <errno.h>

#include <dev/ebpf/ebpf_map.h>
}

namespace {
class PercpuArrayMapLookupTest : public ::testing::Test {
      protected:
	struct ebpf_map map;

	virtual void
	SetUp()
	{
		int error;
		uint32_t gkey = 50;
		uint64_t gval = 100;

		error =
		    ebpf_map_init(&map, EBPF_MAP_TYPE_PERCPU_ARRAY,
				  sizeof(uint32_t), sizeof(uint64_t), 100, 0);
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

TEST_F(PercpuArrayMapLookupTest, LookupMaxEntryPlusOne)
{
	int error;
	uint32_t key = 100;
	uint64_t value;

	error = ebpf_map_lookup_elem_from_user(&map, &key, &value);

	EXPECT_EQ(EINVAL, error);
}

TEST_F(PercpuArrayMapLookupTest, LookupOutOfMaxEntry)
{
	int error;
	uint32_t key = 102;
	uint64_t value;

	error = ebpf_map_lookup_elem_from_user(&map, &key, &value);

	EXPECT_EQ(EINVAL, error);
}

TEST_F(PercpuArrayMapLookupTest, CorrectLookup)
{
	int error;
	uint32_t key = 50;
	uint64_t value[ebpf_ncpus()];

	error = ebpf_map_lookup_elem_from_user(&map, &key, value);

	for (uint16_t i = 0; i < ebpf_ncpus(); i++) {
		EXPECT_EQ(100, value[i]);
	}
}
} // namespace
