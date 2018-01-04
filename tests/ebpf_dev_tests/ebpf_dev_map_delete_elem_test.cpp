#include <gtest/gtest.h>

extern "C" {
#include <stdint.h>
#include <errno.h>
#include <assert.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/ebpf.h>
#include <sys/ebpf_dev.h>
}

static uint32_t key = 1;
static uint32_t value = 100;

namespace {
class EbpfDevMapDeleteElemTest : public ::testing::Test {
  protected:
    int ebpf_fd;
    int map_fd;

    virtual void
    SetUp()
    {
        int error;

        ebpf_fd = open("/dev/ebpf", O_RDWR);
        assert(ebpf_fd > 0);

        union ebpf_req req1;
        req1.map_fdp = &map_fd;
        req1.map_type = EBPF_MAP_TYPE_ARRAY;
        req1.key_size = sizeof(uint32_t);
        req1.value_size = sizeof(uint32_t);
        req1.max_entries = 100;

        error = ioctl(ebpf_fd, EBPFIOC_MAP_CREATE, &req1);
        assert(!error);

        union ebpf_req req2;
        req2.map_fd = map_fd;
        req2.key = &key;
        req2.value = &value;
        req2.flags = 0;

        error = ioctl(ebpf_fd, EBPFIOC_MAP_UPDATE_ELEM, &req2);
        assert(!error);
    }

    virtual void
    TearDown()
    {
        close(ebpf_fd);
        close(map_fd);
    }
};

TEST_F(EbpfDevMapDeleteElemTest, DeleteWithInvalidMapFd)
{
    int error;
    uint32_t k = key;

    union ebpf_req req;
    req.map_fd = 0;
    req.key = &k;
    req.flags = 0;

    error = ioctl(ebpf_fd, EBPFIOC_MAP_DELETE_ELEM, &req);
    EXPECT_EQ(-1, error);
    EXPECT_EQ(EINVAL, errno);
}

TEST_F(EbpfDevMapDeleteElemTest, DeleteWithNullKey)
{
    int error;

    union ebpf_req req;
    req.map_fd = map_fd;
    req.key = NULL;
    req.flags = 0;

    error = ioctl(ebpf_fd, EBPFIOC_MAP_DELETE_ELEM, &req);
    EXPECT_EQ(-1, error);
    EXPECT_EQ(EINVAL, errno);
}

/*
TEST_F(EbpfDevMapDeleteElemTest, DeleteWithInvalidSizeKey) {
  int error;
  uint16_t k = 0;
  uint32_t v = 100;

  union ebpf_req req;
  req.map_fd = map_fd;
  req.key = &k;
  req.value = &v;
  req.flags = 0;

  error = ioctl(ebpf_fd, EBPFIOC_MAP_UPDATE_ELEM, &req);
  EXPECT_EQ(-1, error);
  EXPECT_EQ(EINVAL, errno);
}
*/

TEST_F(EbpfDevMapDeleteElemTest, CorrectDelete)
{
    int error;
    uint32_t k = key;

    union ebpf_req req;
    req.map_fd = map_fd;
    req.key = &k;
    req.flags = 0;

    error = ioctl(ebpf_fd, EBPFIOC_MAP_DELETE_ELEM, &req);
    EXPECT_EQ(0, error);
}
}
