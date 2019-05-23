#include <gtest/gtest.h>

extern "C" {
#include <stdint.h>
#include <errno.h>

#include <dev/ebpf/ebpf_map.h>
}

namespace {
class MapUpdateTest : public ::testing::Test {
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

	error = ebpf_map_update_elem(eom, NULL, &value, EBPF_ANY);

	EXPECT_EQ(EINVAL, error);
}

TEST_F(MapUpdateTest, UpdateWithNULLValue)
{
	int error;
	uint32_t key = 100;

	error = ebpf_map_update_elem(eom, &key, NULL, EBPF_ANY);

	EXPECT_EQ(EINVAL, error);
}

TEST_F(MapUpdateTest, UpdateWithInvalidFlag)
{
	int error;
	uint32_t key = 1, value = 1;

	error = ebpf_map_update_elem(eom, &key, &value, EBPF_EXIST + 1);

	EXPECT_EQ(EINVAL, error);
}
} // namespace
