#include <gtest/gtest.h>

extern "C" {
#include <stdint.h>
#include <errno.h>

#include <dev/ebpf/ebpf_map.h>
}

namespace {
class ArrayMapUpdateTest : public ::testing::Test {
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

TEST_F(ArrayMapUpdateTest, UpdateWithMaxPlusOneKey)
{
	int error;
	uint32_t key = 100, value = 100;

	error = ebpf_map_update_elem_from_user(&map, &key, &value, EBPF_ANY);

	EXPECT_EQ(EINVAL, error);
}

TEST_F(ArrayMapUpdateTest, CorrectUpdate)
{
	int error;
	uint32_t key = 50, value = 100;

	error = ebpf_map_update_elem_from_user(&map, &key, &value, EBPF_ANY);

	EXPECT_EQ(0, error);
}

TEST_F(ArrayMapUpdateTest, CorrectUpdateOverwrite)
{
	int error;
	uint32_t key = 50, value = 100;

	error = ebpf_map_update_elem_from_user(&map, &key, &value, EBPF_ANY);
	ASSERT_TRUE(!error);

	value = 101;
	error = ebpf_map_update_elem_from_user(&map, &key, &value, EBPF_ANY);

	EXPECT_EQ(0, error);
}

TEST_F(ArrayMapUpdateTest, CreateMoreThenMaxEntries)
{
	int error;
	uint32_t key, value = 100;

	for (int i = 0; i < 100; i++) {
		key = i;
		error = ebpf_map_update_elem_from_user(&map, &key, &value, EBPF_ANY);
		ASSERT_TRUE(!error);
	}

	key++;
	error = ebpf_map_update_elem_from_user(&map, &key, &value, EBPF_ANY);

	/*
	 * In array map, max_entries equals to max key, so
	 * returns EINVAL, not EBUSY
	 */
	EXPECT_EQ(EINVAL, error);
}

TEST_F(ArrayMapUpdateTest, UpdateElementWithNOEXISTFlag)
{
	int error;
	uint32_t key = 50, value = 100;

	error = ebpf_map_update_elem_from_user(&map, &key, &value, EBPF_NOEXIST);

	EXPECT_EQ(EEXIST, error);
}
} // namespace
