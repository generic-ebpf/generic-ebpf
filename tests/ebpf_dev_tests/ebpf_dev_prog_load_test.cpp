#include <gtest/gtest.h>

extern "C" {
#include <stdint.h>
#include <errno.h>
#include <assert.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/ebpf.h>
#include <sys/ebpf_inst.h>
#include <sys/ebpf_dev.h>
}

namespace {
class EbpfDevProgLoadTest : public ::testing::Test {
  protected:
    int ebpf_fd;

    virtual void
    SetUp()
    {
        int error;

        ebpf_fd = open("/dev/ebpf", O_RDWR);
        assert(ebpf_fd > 0);
    }

    virtual void
    TearDown()
    {
        close(ebpf_fd);
    }
};

TEST_F(EbpfDevProgLoadTest, LoadWithNullProgFdp)
{
    int error;

    struct ebpf_inst insts[] = {{EBPF_OP_EXIT, 0, 0, 0, 0}};

    union ebpf_req req;
    req.prog_fdp = NULL;
    req.prog_type = EBPF_PROG_TYPE_TEST;
    req.prog = insts;
    req.prog_len = sizeof(struct ebpf_inst) * sizeof(insts);
    req.map_flags = 0;

    error = ioctl(ebpf_fd, EBPFIOC_LOAD_PROG, &req);
    EXPECT_EQ(-1, error);
    EXPECT_EQ(EINVAL, errno);
}

TEST_F(EbpfDevProgLoadTest, LoadWithInvalidProgType1)
{
    int error, fd;

    struct ebpf_inst insts[] = {{EBPF_OP_EXIT, 0, 0, 0, 0}};

    union ebpf_req req;
    req.prog_fdp = &fd;
    req.prog_type = __EBPF_PROG_TYPE_MAX;
    req.prog = insts;
    req.prog_len = sizeof(struct ebpf_inst) * sizeof(insts);
    req.map_flags = 0;

    error = ioctl(ebpf_fd, EBPFIOC_LOAD_PROG, &req);
    EXPECT_EQ(-1, error);
    EXPECT_EQ(EINVAL, errno);
}

TEST_F(EbpfDevProgLoadTest, LoadWithInvalidProgType2)
{
    int error, fd;

    struct ebpf_inst insts[] = {{EBPF_OP_EXIT, 0, 0, 0, 0}};

    union ebpf_req req;
    req.prog_fdp = &fd;
    req.prog_type = __EBPF_PROG_TYPE_MAX + 1;
    req.prog = insts;
    req.prog_len = sizeof(struct ebpf_inst) * sizeof(insts);
    req.map_flags = 0;

    error = ioctl(ebpf_fd, EBPFIOC_LOAD_PROG, &req);
    EXPECT_EQ(-1, error);
    EXPECT_EQ(EINVAL, errno);
}

TEST_F(EbpfDevProgLoadTest, LoadWithNullInsts)
{
    int error, fd;

    union ebpf_req req;
    req.prog_fdp = &fd;
    req.prog_type = EBPF_PROG_TYPE_TEST;
    req.prog = NULL;
    req.prog_len = sizeof(struct ebpf_inst) * 1;
    req.map_flags = 0;

    error = ioctl(ebpf_fd, EBPFIOC_LOAD_PROG, &req);
    EXPECT_EQ(-1, error);
    EXPECT_EQ(EINVAL, errno);
}

TEST_F(EbpfDevProgLoadTest, LoadWithZeroProgLen)
{
    int error, fd;

    struct ebpf_inst insts[] = {{EBPF_OP_EXIT, 0, 0, 0, 0}};

    union ebpf_req req;
    req.prog_fdp = &fd;
    req.prog_type = EBPF_PROG_TYPE_TEST;
    req.prog = insts;
    req.prog_len = 0;
    req.map_flags = 0;

    error = ioctl(ebpf_fd, EBPFIOC_LOAD_PROG, &req);
    EXPECT_EQ(-1, error);
    EXPECT_EQ(EINVAL, errno);
}

TEST_F(EbpfDevProgLoadTest, CorrectLoad)
{
    int error, fd;

    struct ebpf_inst insts[] = {{EBPF_OP_EXIT, 0, 0, 0, 0}};

    union ebpf_req req;
    req.prog_fdp = &fd;
    req.prog_type = EBPF_PROG_TYPE_TEST;
    req.prog = insts;
    req.prog_len = sizeof(struct ebpf_inst) * sizeof(insts);
    req.map_flags = 0;

    error = ioctl(ebpf_fd, EBPFIOC_LOAD_PROG, &req);
    EXPECT_EQ(0, error);

    close(fd);
}
}
