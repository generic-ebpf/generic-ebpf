#include <gtest/gtest.h>

extern "C" {
#include <stdint.h>
#include <errno.h>
#include <dev/ebpf/ebpf_prog.h>
}

TEST(ProgLoadTest, LoadWithNULLProgPointer)
{
    int error;

    struct ebpf_inst insts[] = {{EBPF_OP_EXIT, 0, 0, 0, 0}};

    error = ebpf_prog_init(NULL, EBPF_PROG_TYPE_TEST, insts, 1);

    EXPECT_EQ(EINVAL, error);
}

TEST(ProgLoadTest, LoadWithInvalidProgType1)
{
    int error;
    struct ebpf_prog prog;

    struct ebpf_inst insts[] = {{EBPF_OP_EXIT, 0, 0, 0, 0}};

    error = ebpf_prog_init(&prog, __EBPF_PROG_TYPE_MAX, insts, 1);

    EXPECT_EQ(EINVAL, error);
}

TEST(ProgLoadTest, LoadWithInvalidProgType2)
{
    int error;
    struct ebpf_prog prog;

    struct ebpf_inst insts[] = {{EBPF_OP_EXIT, 0, 0, 0, 0}};

    error = ebpf_prog_init(&prog, __EBPF_PROG_TYPE_MAX + 1, insts, 1);

    EXPECT_EQ(EINVAL, error);
}

TEST(ProgLoadTest, LoadWithZeroLen)
{
    int error;
    struct ebpf_prog prog;

    struct ebpf_inst insts[] = {{EBPF_OP_EXIT, 0, 0, 0, 0}};

    error = ebpf_prog_init(&prog, EBPF_PROG_TYPE_TEST, insts, 0);

    EXPECT_EQ(EINVAL, error);
}

TEST(ProgLoadTest, LoadWithNULLProg)
{
    int error;
    struct ebpf_prog prog;

    error = ebpf_prog_init(&prog, EBPF_PROG_TYPE_TEST, NULL, 1);

    EXPECT_EQ(EINVAL, error);
}

TEST(ProgLoadTest, CorrectLoad)
{
    int error;
    struct ebpf_prog prog;

    struct ebpf_inst insts[] = {{EBPF_OP_EXIT, 0, 0, 0, 0}};

    error = ebpf_prog_init(&prog, EBPF_PROG_TYPE_TEST, insts, 1);

    EXPECT_EQ(0, error);

    ebpf_prog_deinit(&prog, NULL);
}
