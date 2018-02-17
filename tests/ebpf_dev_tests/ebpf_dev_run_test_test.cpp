#include <gtest/gtest.h>

extern "C" {
#include <stdint.h>
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
class EbpfDevRunTestTest : public ::testing::Test {
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

TEST_F(EbpfDevRunTestTest, LoadCtxToR0AndReturn)
{
    int error, prog_fd;

    struct ebpf_inst insts[] = {{EBPF_OP_LDXDW, 0, 1, 0, 0},
                                {EBPF_OP_EXIT, 0, 0, 0, 0}};

    prog_fd =
        ebpf_load_prog(ebpf_fd, EBPF_PROG_TYPE_TEST, insts, sizeof(insts) / 8);
    ASSERT_TRUE(prog_fd > 0);

    uint64_t ctx = 100, result;

    error = ebpf_run_test(ebpf_fd, prog_fd, &ctx, sizeof(uint64_t), 0, &result);
    EXPECT_EQ(0, error);
    EXPECT_EQ(100, result);

    close(prog_fd);
}

TEST_F(EbpfDevRunTestTest, MapLookupFromProg)
{
    int error;
    int map_fd = ebpf_map_create(ebpf_fd, EBPF_MAP_TYPE_ARRAY, sizeof(uint32_t),
                                 sizeof(uint32_t), 100, 0);
    ASSERT_TRUE(map_fd > 0);

    struct ebpf_inst insts[] = {
        {EBPF_OP_LDDW, 1, EBPF_PSEUDO_MAP_DESC, 0, map_fd}, // load mapfd
        {0, 0, 0, 0, 0},
        {EBPF_OP_LDDW, 4, 0, 0, 0}, // key = 0
        {0, 0, 0, 0, 0},
        {EBPF_OP_STXW, 10, 4, -4, 0}, // push key to stack
        {EBPF_OP_MOV64_REG, 2, 10, 0, 0},
        {EBPF_OP_ADD64_IMM, 2, 0, 0, -4}, // get stack address
        {EBPF_OP_MOV64_IMM, 3, 0, 0, 0},  // flags = 0
        {EBPF_OP_CALL, 0, 0, 0, 1},
        {EBPF_OP_MOV64_REG, 1, 0, 0, 0},
        {EBPF_OP_LDXW, 0, 1, 0, 0},
        {EBPF_OP_EXIT, 0, 0, 0, 0}};

    int prog_fd =
        ebpf_load_prog(ebpf_fd, EBPF_PROG_TYPE_TEST, insts, sizeof(insts) / 8);
    ASSERT_TRUE(prog_fd > 0);

    uint32_t k = 0, v = 100;
    error = ebpf_map_update_elem(ebpf_fd, map_fd, &k, &v, 0);
    ASSERT_TRUE(!error);

    uint64_t ctx = 1000, result;
    error = ebpf_run_test(ebpf_fd, prog_fd, &ctx, sizeof(uint64_t), 0, &result);

    EXPECT_EQ(0, error);
    EXPECT_EQ(100, result);

    close(map_fd);
    close(prog_fd);
}
}
