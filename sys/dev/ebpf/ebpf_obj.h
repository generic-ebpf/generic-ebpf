#pragma once

#include "ebpf_platform.h"
#include <sys/ebpf.h>

struct ebpf_obj;

/*
 * ebpf object type description
 */
enum ebpf_obj_type {
  EBPF_OBJ_TYPE_PROG = 0,
  __EBPF_OBJ_TYPE_MAX
};

/*
 * All ebpf object struct must contain below structure
 * on top of it
 */
struct ebpf_obj {
  uint16_t obj_type;
};

/*
 * ebpf program
 */
struct ebpf_obj_prog {
  uint16_t obj_type;
  uint16_t prog_type;
  uint32_t prog_len;
  struct ebpf_inst *prog;
};

bool ebpf_obj_is_type(uint16_t type, struct ebpf_obj *obj);
int ebpf_obj_new(struct ebpf_obj **obj, uint16_t type, union ebpf_req *req);
void ebpf_obj_delete(struct ebpf_obj *obj);
