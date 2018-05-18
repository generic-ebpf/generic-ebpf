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
class EbpfDevMapGetNextKeyElemTest : public ::testing::Test {
      protected:
	int ebpf_fd;
	int map_fd;
	uint32_t key1;
	uint32_t value1;
	uint32_t key2;
	uint32_t value2;

	virtual void
	SetUp()
	{
		int error;
		key1 = 1;
		value1 = 100;
		key2 = 3;
		value2 = 200;

		ebpf_fd = open("/dev/ebpf", O_RDWR);
		ASSERT_TRUE(ebpf_fd > 0);

		union ebpf_req req1;
		req1.map_fdp = &map_fd;
		req1.map_type = EBPF_MAP_TYPE_ARRAY;
		req1.key_size = sizeof(uint32_t);
		req1.value_size = sizeof(uint32_t);
		req1.max_entries = 100;

		error = ioctl(ebpf_fd, EBPFIOC_MAP_CREATE, &req1);
		ASSERT_TRUE(!error);

		union ebpf_req req2;
		req2.map_fd = map_fd;
		req2.key = &key1;
		req2.value = &value1;
		req2.flags = 0;

		error = ioctl(ebpf_fd, EBPFIOC_MAP_UPDATE_ELEM, &req2);
		ASSERT_TRUE(!error);

		union ebpf_req req3;
		req3.map_fd = map_fd;
		req3.key = &key2;
		req3.value = &value2;
		req3.flags = 0;

		error = ioctl(ebpf_fd, EBPFIOC_MAP_UPDATE_ELEM, &req3);
		ASSERT_TRUE(!error);
	}

	virtual void
	TearDown()
	{
		close(ebpf_fd);
		close(map_fd);
	}
};

TEST_F(EbpfDevMapGetNextKeyElemTest, GetNextKeyWithInvalidMapFd)
{
	int error;
	uint32_t k = key1, next_key;

	union ebpf_req req;
	req.map_fd = 0;
	req.key = &k;
	req.next_key = &next_key;
	req.flags = 0;

	error = ioctl(ebpf_fd, EBPFIOC_MAP_GET_NEXT_KEY, &req);
	EXPECT_EQ(-1, error);
	EXPECT_EQ(EINVAL, errno);
}

TEST_F(EbpfDevMapGetNextKeyElemTest, GetNextKeyWithNullKey)
{
	int error;
	uint32_t next_key;

	union ebpf_req req;
	req.map_fd = map_fd;
	req.key = NULL;
	req.next_key = &next_key;
	req.flags = 0;

	error = ioctl(ebpf_fd, EBPFIOC_MAP_GET_NEXT_KEY, &req);
	EXPECT_EQ(-1, error);
	EXPECT_EQ(EINVAL, errno);
}

/*
TEST_F(EbpfDevMapGetNextKeyElemTest, GetNextKeyWithInvalidSizeKey) {
  int error;
  uint16_t k = 0;
  uint32_t v = 100;

  union ebpf_req req;
  req.map_fd = map_fd;
  req.key = &k;
  req.value = &v;
  req.flags = 0;

  error = ioctl(ebpf_fd, EBPFIOC_MAP_GET_NEXT_KEY, &req);
  EXPECT_EQ(-1, error);
  EXPECT_EQ(EINVAL, errno);
}
*/

TEST_F(EbpfDevMapGetNextKeyElemTest, CorrectGetNextKey)
{
	int error;
	uint32_t k = key1, next_key;

	union ebpf_req req;
	req.map_fd = map_fd;
	req.key = &k;
	req.next_key = &next_key;
	req.flags = 0;

	error = ioctl(ebpf_fd, EBPFIOC_MAP_GET_NEXT_KEY, &req);
	EXPECT_EQ(0, error);
}
}
