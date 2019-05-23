#include <gtest/gtest.h>

extern "C" {
#include <stdint.h>
#include <errno.h>

#include <dev/ebpf/ebpf_map.h>
}

namespace {
class MapLookupTest : public ::testing::Test {
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

TEST_F(MapLookupTest, LookupWithNULLMap)
{
	int error;
	uint32_t key = 50;
	void *value;

	value = ebpf_map_lookup_elem(NULL, (void *)&key);

	EXPECT_EQ(NULL, value);
}

TEST_F(MapLookupTest, LookupWithNULLKey)
{
	int error;
	void *value;

	value = ebpf_map_lookup_elem(eom, NULL);

	EXPECT_EQ(NULL, value);
}

TEST_F(MapLookupTest, LookupWithNULLValue)
{
	int error;
	uint32_t key = 100;
	void *value;

	value = ebpf_map_lookup_elem(eom, (void *)&key);

	EXPECT_EQ(NULL, value);
}
} // namespace
