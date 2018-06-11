#include <gtest/gtest.h>

extern "C" {
#include <stdint.h>
#include <errno.h>

#include <dev/ebpf/ebpf_map.h>
}

namespace {
class ArrayMapLookupTest : public ::testing::Test {
      protected:
	struct ebpf_map map;

	virtual void
	SetUp()
	{
		int error;
		uint32_t gkey = 50, gval = 100;

		error =
		    ebpf_map_init(&map, EBPF_MAP_TYPE_ARRAY, sizeof(uint32_t),
				  sizeof(uint32_t), 100, 0);
		ASSERT_TRUE(!error);

		error = ebpf_map_update_elem(&map, &gkey, &gval, 0);
		ASSERT_TRUE(!error);
	}

	virtual void
	TearDown()
	{
		ebpf_map_deinit(&map, NULL);
	}
};

TEST_F(ArrayMapLookupTest, LookupMaxEntryPlusOne)
{
	int error;
	uint32_t key = 100;
	void *value;

	value = ebpf_map_lookup_elem(&map, &key, 0);

	EXPECT_EQ(NULL, value);
}

TEST_F(ArrayMapLookupTest, LookupOutOfMaxEntry)
{
	int error;
	uint32_t key = 102;
	void *value;

	value = ebpf_map_lookup_elem(&map, &key, 0);

	EXPECT_EQ(NULL, value);
}

TEST_F(ArrayMapLookupTest, CorrectLookup)
{
	int error;
	uint32_t key = 50;
	uint32_t *value;

	value = (uint32_t *)ebpf_map_lookup_elem(&map, &key, 0);

	EXPECT_EQ(100, *value);
}
} // namespace
