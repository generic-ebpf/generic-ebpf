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

	virtual void
	SetUp()
	{
		int error;

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
	uint32_t k = 1, next_key;

	union ebpf_req req;
	req.map_fd = 0;
	req.key = &k;
	req.next_key = &next_key;
	req.flags = 0;

	error = ioctl(ebpf_fd, EBPFIOC_MAP_GET_NEXT_KEY, &req);
	EXPECT_EQ(-1, error);
	EXPECT_EQ(EINVAL, errno);
}

TEST_F(EbpfDevMapGetNextKeyElemTest, CorrectGetNextKey)
{
	int error;
	bool discovered[100];

	union ebpf_req req1;
	req1.map_fd = map_fd;
	req1.flags = 0;

	for (uint32_t i = 0; i < 100; i++) {
		discovered[i] = false;
		req1.key = &i;
		req1.value = &i;
		error = ioctl(ebpf_fd, EBPFIOC_MAP_UPDATE_ELEM, &req1);
		ASSERT_TRUE(!error);
	}

	uint32_t next_key;
	union ebpf_req req2;
	req2.map_fd = map_fd;
	req2.key = NULL;
	req2.next_key = &next_key;
	req2.flags = 0;
	error = ioctl(ebpf_fd, EBPFIOC_MAP_GET_NEXT_KEY, &req2);
	discovered[next_key] = true;

	while (!error) {
		req2.key = &next_key;
		req2.next_key = &next_key;
		error = ioctl(ebpf_fd, EBPFIOC_MAP_GET_NEXT_KEY, &req2);
		discovered[next_key] = true;
	}

	for (uint32_t i = 0; i < 100; i++) {
		EXPECT_EQ(discovered[i], true);
	}
}
} // namespace
