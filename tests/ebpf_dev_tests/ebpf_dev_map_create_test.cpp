#include <gtest/gtest.h>

extern "C" {
#include <stdint.h>
#include <errno.h>

#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/ebpf.h>
#include <sys/ebpf_dev.h>
}

namespace {
class EbpfDevMapCreateTest : public ::testing::Test {
      protected:
	int ebpf_fd;

	virtual void
	SetUp()
	{
		int error;

		ebpf_fd = open("/dev/ebpf", O_RDWR);
		ASSERT_TRUE(ebpf_fd > 0);
	}

	virtual void
	TearDown()
	{
		close(ebpf_fd);
	}
};

TEST_F(EbpfDevMapCreateTest, CreateWithNullMapFdp)
{
	int error;

	union ebpf_req req;
	req.map_fdp = NULL;
	req.map_type = EBPF_MAP_TYPE_ARRAY;
	req.key_size = sizeof(uint32_t);
	req.value_size = sizeof(uint32_t);
	req.max_entries = 100;
	req.map_flags = 0;

	error = ioctl(ebpf_fd, EBPFIOC_MAP_CREATE, &req);
	EXPECT_EQ(-1, error);
	EXPECT_EQ(EINVAL, errno);
}

TEST_F(EbpfDevMapCreateTest, CreateWithInvalidMapType1)
{
	int fd, error;

	union ebpf_req req;
	req.map_fdp = &fd;
	req.map_type = __EBPF_MAP_TYPE_MAX;
	req.key_size = sizeof(uint32_t);
	req.value_size = sizeof(uint32_t);
	req.max_entries = 100;
	req.map_flags = 0;

	error = ioctl(ebpf_fd, EBPFIOC_MAP_CREATE, &req);
	EXPECT_EQ(-1, error);
	EXPECT_EQ(EINVAL, errno);
}

TEST_F(EbpfDevMapCreateTest, CreateWithInvalidMapType2)
{
	int fd, error;

	union ebpf_req req;
	req.map_fdp = &fd;
	req.map_type = __EBPF_MAP_TYPE_MAX + 1;
	req.key_size = sizeof(uint32_t);
	req.value_size = sizeof(uint32_t);
	req.max_entries = 100;
	req.map_flags = 0;

	error = ioctl(ebpf_fd, EBPFIOC_MAP_CREATE, &req);
	EXPECT_EQ(-1, error);
	EXPECT_EQ(EINVAL, errno);
}

TEST_F(EbpfDevMapCreateTest, CreateWithZeroKeySize)
{
	int fd, error;

	union ebpf_req req;
	req.map_fdp = &fd;
	req.map_type = EBPF_MAP_TYPE_ARRAY;
	req.key_size = 0;
	req.value_size = sizeof(uint32_t);
	req.max_entries = 100;
	req.map_flags = 0;

	error = ioctl(ebpf_fd, EBPFIOC_MAP_CREATE, &req);
	EXPECT_EQ(-1, error);
	EXPECT_EQ(EINVAL, errno);
}

TEST_F(EbpfDevMapCreateTest, CreateWithZeroValueSize)
{
	int fd, error;

	union ebpf_req req;
	req.map_fdp = &fd;
	req.map_type = EBPF_MAP_TYPE_ARRAY;
	req.key_size = sizeof(uint32_t);
	req.value_size = 0;
	req.max_entries = 100;
	req.map_flags = 0;

	error = ioctl(ebpf_fd, EBPFIOC_MAP_CREATE, &req);
	EXPECT_EQ(-1, error);
	EXPECT_EQ(EINVAL, errno);
}

TEST_F(EbpfDevMapCreateTest, CreateWithZeroMaxEntries)
{
	int fd, error;

	union ebpf_req req;
	req.map_fdp = &fd;
	req.map_type = EBPF_MAP_TYPE_ARRAY;
	req.key_size = sizeof(uint32_t);
	req.value_size = sizeof(uint32_t);
	req.max_entries = 0;
	req.map_flags = 0;

	error = ioctl(ebpf_fd, EBPFIOC_MAP_CREATE, &req);
	EXPECT_EQ(-1, error);
	EXPECT_EQ(EINVAL, errno);
}

TEST_F(EbpfDevMapCreateTest, CorrectCreateArrayMap)
{
	int fd, error;

	union ebpf_req req;
	req.map_fdp = &fd;
	req.map_type = EBPF_MAP_TYPE_ARRAY;
	req.key_size = sizeof(uint32_t);
	req.value_size = sizeof(uint32_t);
	req.max_entries = 100;
	req.map_flags = 0;

	error = ioctl(ebpf_fd, EBPFIOC_MAP_CREATE, &req);
	EXPECT_EQ(0, error);
	close(fd);
}

TEST_F(EbpfDevMapCreateTest, CorrectCreateTommyHashMap)
{
	int fd, error;

	union ebpf_req req;
	req.map_fdp = &fd;
	req.map_type = EBPF_MAP_TYPE_HASHTABLE;
	req.key_size = sizeof(uint32_t);
	req.value_size = sizeof(uint32_t);
	req.max_entries = 100;
	req.map_flags = 0;

	error = ioctl(ebpf_fd, EBPFIOC_MAP_CREATE, &req);
	EXPECT_EQ(0, error);
	close(fd);
}
} // namespace
