#include <gtest/gtest.h>

extern "C" {
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

#include <sys/ebpf_dev.h>
}

namespace {
class EbpfDevHashTableMapTest : public ::testing::Test {
      protected:
	int ebpf_fd;
	int map_fd;

	virtual void
	SetUp()
	{
		int error;
		ebpf_fd = open("/dev/ebpf", O_RDWR);
		ASSERT_TRUE(ebpf_fd > 0);

		union ebpf_req req;
		req.map_fdp = &map_fd;
		req.map_type = EBPF_MAP_TYPE_HASHTABLE;
		req.key_size = sizeof(uint32_t);
		req.value_size = sizeof(uint32_t);
		req.max_entries = 100;

		error = ioctl(ebpf_fd, EBPFIOC_MAP_CREATE, &req);
		ASSERT_TRUE(error == 0);
	}

	virtual void
	TearDown()
	{
		close(ebpf_fd);
		close(map_fd);
	}
};

TEST_F(EbpfDevHashTableMapTest, CorrectUpdate)
{
	int error;
	uint32_t k = 50, v = 100;

	union ebpf_req req;
	req.map_fd = map_fd;
	req.key = &k;
	req.value = &v;
	req.flags = EBPF_ANY;

	error = ioctl(ebpf_fd, EBPFIOC_MAP_UPDATE_ELEM, &req);
	EXPECT_EQ(0, error);
}

TEST_F(EbpfDevHashTableMapTest, CorrectUpdateMoreThanMaxEntries)
{
	int error;
	uint32_t i;
	union ebpf_req req;

	for (i = 0; i < 100; i++) {
		req.map_fd = map_fd;
		req.key = &i;
		req.value = &i;
		req.flags = EBPF_ANY;
		error = ioctl(ebpf_fd, EBPFIOC_MAP_UPDATE_ELEM, &req);
		ASSERT_TRUE(!error);
	}

	error = ioctl(ebpf_fd, EBPFIOC_MAP_UPDATE_ELEM, &req);
	EXPECT_EQ(-1, error);
	EXPECT_EQ(EBUSY, errno);
}

TEST_F(EbpfDevHashTableMapTest, UpdateExistingElementWithNOEXISTFlag)
{
	int error;
	uint32_t key = 50, value = 100;

	union ebpf_req req;
	req.map_fd = map_fd;
	req.key = &key;
	req.value = &value;
	req.flags = EBPF_ANY;

	error = ioctl(ebpf_fd, EBPFIOC_MAP_UPDATE_ELEM, &req);
	ASSERT_TRUE(!error);

	req.flags = EBPF_NOEXIST;
	error = ioctl(ebpf_fd, EBPFIOC_MAP_UPDATE_ELEM, &req);
	EXPECT_EQ(-1, error);
	EXPECT_EQ(EEXIST, errno);
}

TEST_F(EbpfDevHashTableMapTest, UpdateNonExistingElementWithNOEXISTFlag)
{
	int error;
	uint32_t key = 50, value = 100;

	union ebpf_req req;
	req.map_fd = map_fd;
	req.key = &key;
	req.value = &value;
	req.flags = EBPF_NOEXIST;

	error = ioctl(ebpf_fd, EBPFIOC_MAP_UPDATE_ELEM, &req);
	EXPECT_EQ(0, error);
}

TEST_F(EbpfDevHashTableMapTest, UpdateNonExistingElementWithEXISTFlag)
{
	int error;
	uint32_t key = 50, value = 100;

	union ebpf_req req;
	req.map_fd = map_fd;
	req.key = &key;
	req.value = &value;
	req.flags = EBPF_EXIST;

	error = ioctl(ebpf_fd, EBPFIOC_MAP_UPDATE_ELEM, &req);
	EXPECT_EQ(-1, error);
	EXPECT_EQ(ENOENT, errno);
}

TEST_F(EbpfDevHashTableMapTest, UpdateExistingElementWithEXISTFlag)
{
	int error;
	uint32_t key = 50, value = 100;

	union ebpf_req req;
	req.map_fd = map_fd;
	req.key = &key;
	req.value = &value;
	req.flags = EBPF_ANY;

	error = ioctl(ebpf_fd, EBPFIOC_MAP_UPDATE_ELEM, &req);
	EXPECT_EQ(0, error);

	req.flags = EBPF_EXIST;
	value++;
	error = ioctl(ebpf_fd, EBPFIOC_MAP_UPDATE_ELEM, &req);
	EXPECT_EQ(0, error);
}

TEST_F(EbpfDevHashTableMapTest, CorrectDelete)
{
	int error;
	uint32_t key = 50;

	union ebpf_req req;
	req.map_fd = map_fd;
	req.key = &key;

	error = ioctl(ebpf_fd, EBPFIOC_MAP_DELETE_ELEM, &req);
	EXPECT_EQ(0, error);
}

TEST_F(EbpfDevHashTableMapTest, GetFirstKey)
{
	int error;
	uint32_t key = 100, value = 200, next_key = 0;

	union ebpf_req req1;
	req1.map_fd = map_fd;
	req1.key = &key;
	req1.value = &value;
	req1.flags = EBPF_ANY;

	error = ioctl(ebpf_fd, EBPFIOC_MAP_UPDATE_ELEM, &req1);
	EXPECT_EQ(0, error);

	union ebpf_req req2;
	req2.map_fd = map_fd;
	req2.key = NULL;
	req2.next_key = &next_key;

	error = ioctl(ebpf_fd, EBPFIOC_MAP_GET_NEXT_KEY, &req2);
	EXPECT_EQ(0, error);
	EXPECT_EQ(100, next_key);
}

TEST_F(EbpfDevHashTableMapTest, CorrectGetNextKey)
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

TEST_F(EbpfDevHashTableMapTest, LookupUnexistingEntry)
{
	int error;
	uint32_t key = 51;
	uint32_t value;

	union ebpf_req req;
	req.map_fd = map_fd;
	req.key = &key;
	req.value = &value;

	error = ioctl(ebpf_fd, EBPFIOC_MAP_LOOKUP_ELEM, &req);
	EXPECT_EQ(-1, error);
	EXPECT_EQ(ENOENT, errno);
}

TEST_F(EbpfDevHashTableMapTest, CorrectLookup)
{
	int error;
	uint32_t key = 50, val = 100;
	uint32_t value;

	union ebpf_req req;
	req.map_fd = map_fd;
	req.key = &key;
	req.value = &val;
	req.flags = EBPF_ANY;

	error = ioctl(ebpf_fd, EBPFIOC_MAP_UPDATE_ELEM, &req);
	EXPECT_EQ(0, error);

	req.value = &value;
	error = ioctl(ebpf_fd, EBPFIOC_MAP_LOOKUP_ELEM, &req);
	EXPECT_EQ(0, error);

	EXPECT_EQ(100, value);
}
} // namespace
