#include <gtest/gtest.h>

extern "C" {
#include <stdint.h>
#include <errno.h>

#include <dev/ebpf/ebpf_map.h>
}

namespace {
class PercpuArrayMapGetNextKeyTest : public ::testing::Test {
      protected:
	struct ebpf_map *em;

	virtual void
	SetUp()
	{
	  struct ebpf_map_attr attr;
	  attr.type = EBPF_MAP_TYPE_PERCPU_ARRAY;
	  attr.key_size = sizeof(uint32_t);
	  attr.value_size = sizeof(uint32_t);
	  attr.max_entries = 100;
	  attr.flags = 0;

		int error = ebpf_map_create(&em, &attr);
		ASSERT_TRUE(!error);
	}

	virtual void
	TearDown()
	{
		ebpf_map_destroy(em);
	}
};

TEST_F(PercpuArrayMapGetNextKeyTest, GetNextKeyWithMaxKey)
{
	int error;
	uint32_t key = 99, next_key = 0;

	error = ebpf_map_get_next_key_from_user(em, &key, &next_key);

	EXPECT_EQ(ENOENT, error);
}

TEST_F(PercpuArrayMapGetNextKeyTest, GetFirstKey)
{
	int error;
	uint32_t next_key = 0;

	error = ebpf_map_get_next_key_from_user(em, NULL, &next_key);

	EXPECT_EQ(0, error);
	EXPECT_EQ(0, next_key);
}

TEST_F(PercpuArrayMapGetNextKeyTest, CorrectGetNextKey)
{
	int error;
	uint32_t key = 50, next_key = 0;

	error = ebpf_map_get_next_key_from_user(em, &key, &next_key);

	EXPECT_EQ(0, error);
	EXPECT_EQ(51, next_key);
}
} // namespace
