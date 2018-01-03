#include <gtest/gtest.h>

extern "C" {
#include <stdint.h>
#include <errno.h>
#include <sys/time.h>
#include <assert.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/ebpf.h>
#include <sys/ebpf_dev.h>
}

namespace {
class EbpfDevRunTestTest : public ::testing::Test {
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

TEST_F(EbpfDevRunTestTest, LoadCtxToR0AndReturn)
{
    int error, prog_fd;

    struct ebpf_inst insts[] = {
        {EBPF_OP_LDXDW, 0, 1, 0, 0},
        {EBPF_OP_EXIT, 0, 0, 0, 0}
    };

    union ebpf_req req;
    req.prog_fdp = &prog_fd;
    req.prog_type = EBPF_PROG_TYPE_TEST;
    req.prog = insts;
    req.prog_len = 2;
    req.map_flags = 0;

    error = ioctl(ebpf_fd, EBPFIOC_LOAD_PROG, &req);
    assert(!error);

    uint64_t ctx = 100, result;

    union ebpf_req test_req;
    test_req.prog_fd = prog_fd;
    test_req.ctx = &ctx;
    test_req.ctx_len = sizeof(uint64_t);
    test_req.jit = 0;
    test_req.test_result = &result;

    error = ioctl(ebpf_fd, EBPFIOC_RUN_TEST, &test_req);
    EXPECT_EQ(0, error);
    EXPECT_EQ(100, result);
}

TEST_F(EbpfDevRunTestTest, MapLookupFromProg)
{
    int error, map_fd;

    union ebpf_req map_req;
    map_req.map_fdp = &map_fd;
    map_req.map_type = EBPF_MAP_TYPE_ARRAY;
    map_req.key_size = sizeof(uint32_t);
    map_req.value_size = sizeof(uint32_t);
    map_req.max_entries = 100;
    map_req.map_flags = 0;

    error = ioctl(ebpf_fd, EBPFIOC_MAP_CREATE, &map_req);
    assert(!error);

    struct ebpf_inst insts[] = {
        {EBPF_OP_LDDW, 1, EBPF_PSEUDO_MAPFD, 0, map_fd}, // load mapfd
        {0, 0, 0, 0, 0},
        {EBPF_OP_LDDW, 4, 0, 0, 0}, // key = 0
        {0, 0, 0, 0, 0},
        {EBPF_OP_STXW, 10, 4, -4, 0}, // push key to stack
        {EBPF_OP_MOV64_REG, 2, 10, 0, 0},
        {EBPF_OP_ADD64_IMM, 2, 0, 0, -4}, // get stack address
        {EBPF_OP_MOV64_IMM, 3, 0, 0, 0}, // flags = 0 
        {EBPF_OP_CALL, 0, 0, 0, TEST_CALL_EBPF_MAP_LOOKUP_ELEM},
        {EBPF_OP_MOV64_REG, 1, 0, 0, 0},
        {EBPF_OP_LDXW, 0, 1, 0, 0},
        {EBPF_OP_EXIT, 0, 0, 0, 0}
    };

    int prog_fd;
    union ebpf_req prog_req;
    prog_req.prog_fdp = &prog_fd;
    prog_req.prog_type = EBPF_PROG_TYPE_TEST;
    prog_req.prog = insts;
    prog_req.prog_len = 12;

    error = ioctl(ebpf_fd, EBPFIOC_LOAD_PROG, &prog_req);
    assert(!error); 

    uint32_t k = 0, v = 100;
    union ebpf_req map_update_req;
    map_update_req.map_fd = map_fd;
    map_update_req.key = &k;
    map_update_req.value = &v;
    map_update_req.flags = 0;

    error = ioctl(ebpf_fd, EBPFIOC_MAP_UPDATE_ELEM, &map_update_req);
    assert(!error);

    sleep(5);

    uint64_t ctx = 1000, result;
    union ebpf_req test_req;
    test_req.prog_fd = prog_fd;
    test_req.ctx = &ctx;
    test_req.ctx_len = sizeof(uint64_t);
    test_req.jit = 0;
    test_req.test_result = &result;

    error = ioctl(ebpf_fd, EBPFIOC_RUN_TEST, &test_req);
    EXPECT_EQ(0, error);
    EXPECT_EQ(100, result);
}
}
