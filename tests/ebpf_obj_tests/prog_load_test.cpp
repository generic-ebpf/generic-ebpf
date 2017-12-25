#include <gtest/gtest.h>

extern "C" {
#include <stdint.h>
#include <errno.h>
#include <dev/ebpf/ebpf_obj.h>
}

TEST(ProgLoadTest, LoadWithNULLProgPointer)
{
  int error;

  struct ebpf_inst insts[] = {
    { EBPF_OP_EXIT, 0, 0, 0, 0 }
  };

  union ebpf_req req;
  req.prog_fdp = NULL;
  req.prog_type = EBPF_PROG_TYPE_TEST;
  req.prog_len = 1;
  req.prog = insts;

  error = ebpf_obj_new(NULL, EBPF_OBJ_TYPE_PROG, &req);

  EXPECT_EQ(EINVAL, error);
}

TEST(ProgLoadTest, LoadWithNULLReq)
{
  int error;
  struct ebpf_obj_prog *prog;

  error = ebpf_obj_new((struct ebpf_obj **)&prog, EBPF_OBJ_TYPE_PROG, NULL);

  EXPECT_EQ(EINVAL, error);
}

TEST(ProgLoadTest, LoadWithInvalidProgType1)
{
  int error;
  struct ebpf_obj_prog *prog;

  struct ebpf_inst insts[] = {
    { EBPF_OP_EXIT, 0, 0, 0, 0 }
  };

  union ebpf_req req;
  req.prog_fdp = NULL;
  req.prog_type = __EBPF_PROG_TYPE_MAX;
  req.prog_len = 1;
  req.prog = insts;

  error = ebpf_obj_new((struct ebpf_obj **)&prog, EBPF_OBJ_TYPE_PROG, &req);

  EXPECT_EQ(EINVAL, error);
}

TEST(ProgLoadTest, LoadWithInvalidProgType2)
{
  int error;
  struct ebpf_obj_prog *prog;

  struct ebpf_inst insts[] = {
    { EBPF_OP_EXIT, 0, 0, 0, 0 }
  };

  union ebpf_req req;
  req.prog_fdp = NULL;
  req.prog_type = __EBPF_PROG_TYPE_MAX + 1;
  req.prog_len = 1;
  req.prog = insts;

  error = ebpf_obj_new((struct ebpf_obj **)&prog, EBPF_OBJ_TYPE_PROG, &req);

  EXPECT_EQ(EINVAL, error);
}

TEST(ProgLoadTest, LoadWithZeroLen)
{
  int error;
  struct ebpf_obj_prog *prog;

  struct ebpf_inst insts[] = {
    { EBPF_OP_EXIT, 0, 0, 0, 0 }
  };

  union ebpf_req req;
  req.prog_fdp = NULL;
  req.prog_type = EBPF_PROG_TYPE_TEST;
  req.prog_len = 0;
  req.prog = insts;

  error = ebpf_obj_new((struct ebpf_obj **)&prog, EBPF_OBJ_TYPE_PROG, &req);

  EXPECT_EQ(EINVAL, error);
}

TEST(ProgLoadTest, LoadWithNULLProg)
{
  int error;
  struct ebpf_obj_prog *prog;

  struct ebpf_inst insts[] = {
    { EBPF_OP_EXIT, 0, 0, 0, 0 }
  };

  union ebpf_req req;
  req.prog_fdp = NULL;
  req.prog_type = EBPF_PROG_TYPE_TEST;
  req.prog_len = 1;
  req.prog = NULL;

  error = ebpf_obj_new((struct ebpf_obj **)&prog, EBPF_OBJ_TYPE_PROG, &req);

  EXPECT_EQ(EINVAL, error);
}
