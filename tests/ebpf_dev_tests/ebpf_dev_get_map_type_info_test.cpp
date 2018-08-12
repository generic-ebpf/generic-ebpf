#include <gtest/gtest.h>

extern "C" {
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <sys/time.h>

#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/ebpf.h>
#include <sys/ebpf_inst.h>
#include <sys/ebpf_dev.h>
#include "util.h"
}

namespace {
class EbpfDevGetMapTypeInfoTest : public ::testing::Test {
      protected:
	int ebpf_fd;

	virtual void
	SetUp()
	{
		int error;

		ebpf_fd = ebpf_init();
		ASSERT_TRUE(ebpf_fd > 0);
	}

	virtual void
	TearDown()
	{
		ebpf_done(ebpf_fd);
	}
};

TEST_F(EbpfDevGetMapTypeInfoTest, GetWithInvalidMapId)
{
	int error;
	struct ebpf_map_type_info info;

	error = ebpf_get_map_type_info(ebpf_fd, __EBPF_MAP_TYPE_MAX, &info);
	EXPECT_EQ(-1, error);
	EXPECT_EQ(EINVAL, errno);
}

TEST_F(EbpfDevGetMapTypeInfoTest, CheckBasicMapInfo)
{
	int error;
	struct ebpf_map_type_info info;

	error = ebpf_get_map_type_info(ebpf_fd, EBPF_MAP_TYPE_BAD, &info);
	EXPECT_EQ(0, error);
	EXPECT_EQ(0, strcmp(info.name, "bad"));

	error = ebpf_get_map_type_info(ebpf_fd, EBPF_MAP_TYPE_ARRAY, &info);
	EXPECT_EQ(0, error);
	EXPECT_EQ(0, strcmp(info.name, "array"));

	error = ebpf_get_map_type_info(ebpf_fd, EBPF_MAP_TYPE_PERCPU_ARRAY, &info);
	EXPECT_EQ(0, error);
	EXPECT_EQ(0, strcmp(info.name, "percpu_array"));

	error = ebpf_get_map_type_info(ebpf_fd, EBPF_MAP_TYPE_HASHTABLE, &info);
	EXPECT_EQ(0, error);
	EXPECT_EQ(0, strcmp(info.name, "hashtable"));

	error = ebpf_get_map_type_info(ebpf_fd, EBPF_MAP_TYPE_PERCPU_HASHTABLE, &info);
	EXPECT_EQ(0, error);
	EXPECT_EQ(0, strcmp(info.name, "percpu_hashtable"));
}
}
