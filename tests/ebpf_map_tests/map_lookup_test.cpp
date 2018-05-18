#include <gtest/gtest.h>

extern "C" {
#include <stdint.h>
#include <errno.h>

#include <dev/ebpf/ebpf_map.h>
}

namespace {
class MapLookupTest : public ::testing::Test {
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

TEST_F(MapLookupTest, LookupWithNULLMap)
{
	int error;
	uint32_t key = 50;
	void *value;

	value = ebpf_map_lookup_elem(NULL, (void *)&key, 0);

	EXPECT_EQ(NULL, value);
}

TEST_F(MapLookupTest, LookupWithNULLKey)
{
	int error;
	void *value;

	value = ebpf_map_lookup_elem(&map, NULL, 0);

	EXPECT_EQ(NULL, value);
}

TEST_F(MapLookupTest, LookupWithNULLValue)
{
	int error;
	uint32_t key = 100;
	void *value;

	value = ebpf_map_lookup_elem(&map, (void *)&key, 0);

	EXPECT_EQ(NULL, value);
}
}
