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
class EbpfDevMapUpdateElemTest : public ::testing::Test {
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
        req.map_type = EBPF_MAP_TYPE_ARRAY;
        req.key_size = sizeof(uint32_t);
        req.value_size = sizeof(uint32_t);
        req.max_entries = 100;

        error = ioctl(ebpf_fd, EBPFIOC_MAP_CREATE, &req);
        ASSERT_TRUE(!error);
    }

    virtual void
    TearDown()
    {
        close(ebpf_fd);
        close(map_fd);
    }
};

TEST_F(EbpfDevMapUpdateElemTest, UpdateWithInvalidMapFd)
{
    int error;
    uint32_t k = 0, v = 100;

    union ebpf_req req;
    req.map_fd = 0;
    req.key = &k;
    req.value = &v;
    req.flags = 0;

    error = ioctl(ebpf_fd, EBPFIOC_MAP_UPDATE_ELEM, &req);
    EXPECT_EQ(-1, error);
    EXPECT_EQ(EINVAL, errno);
}

TEST_F(EbpfDevMapUpdateElemTest, UpdateWithNullKey)
{
    int error;
    uint32_t v = 100;

    union ebpf_req req;
    req.map_fd = map_fd;
    req.key = NULL;
    req.value = &v;
    req.flags = 0;

    error = ioctl(ebpf_fd, EBPFIOC_MAP_UPDATE_ELEM, &req);
    EXPECT_EQ(-1, error);
    EXPECT_EQ(EINVAL, errno);
}

TEST_F(EbpfDevMapUpdateElemTest, UpdateWithNullValue)
{
    int error;
    uint32_t k = 0;

    union ebpf_req req;
    req.map_fd = map_fd;
    req.key = &k;
    req.value = NULL;
    req.flags = 0;

    error = ioctl(ebpf_fd, EBPFIOC_MAP_UPDATE_ELEM, &req);
    EXPECT_EQ(-1, error);
    EXPECT_EQ(EINVAL, errno);
}

/*
TEST_F(EbpfDevMapUpdateElemTest, UpdateWithInvalidSizeKey) {
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

TEST_F(EbpfDevMapUpdateElemTest, UpdateWithInvalidSizeValue) {
  int error;
  uint32_t k = 0;
  uint16_t v = 100;

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

TEST_F(EbpfDevMapUpdateElemTest, CorrectUpdate)
{
    int error;
    uint32_t k = 0, v = 100;

    union ebpf_req req;
    req.map_fd = map_fd;
    req.key = &k;
    req.value = &v;
    req.flags = 0;

    error = ioctl(ebpf_fd, EBPFIOC_MAP_UPDATE_ELEM, &req);
    EXPECT_EQ(0, error);
}

TEST_F(EbpfDevMapUpdateElemTest, CorrectUpdateMoreThanMaxEntries)
{
    int error;

    union ebpf_req req;
    for (uint32_t i = 0; i < 101; i++) {
        req.map_fd = map_fd;
        req.key = &i;
        req.value = &i;
        req.flags = 0;
        error = ioctl(ebpf_fd, EBPFIOC_MAP_UPDATE_ELEM, &req);
        if (i == 100) {
            EXPECT_EQ(-1, error);
            EXPECT_EQ(EBUSY, errno);
        }
    }
}
}
