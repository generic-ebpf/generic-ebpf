#include "ebpf_obj.h"

/* 
 * Constructor of ebpf program
 */
static int
ebpf_obj_prog_ctor(struct ebpf_obj_prog *obj, union ebpf_req *req)
{
  if (req->prog_type >= __EBPF_PROG_TYPE_MAX) {
    return EINVAL;
  }

  struct ebpf_inst *prog =
    ebpf_calloc(req->prog_len, 1);
  if (!prog) {
    return ENOMEM;
  }

  memcpy(prog, req->prog, req->prog_len);

  obj->prog_type = req->prog_type;
  obj->prog_len = req->prog_len;
  obj->prog = prog;

  ebpf_error("ebpf_obj_prog_ctor\n");

  return 0;
}

/*
 * Destructor of ebpf program
 */
static void
ebpf_obj_prog_dtor(struct ebpf_obj_prog *obj)
{
  struct ebpf_obj_prog *prog_obj;
  prog_obj = (struct ebpf_obj_prog *)obj;

  ebpf_free(prog_obj->prog);
  ebpf_error("ebpf_obj_prog_dtor\n");
}

int
ebpf_obj_new(struct ebpf_obj **obj, uint16_t type, union ebpf_req *req)
{
  int error;

  switch (type) {
    case EBPF_OBJ_TYPE_PROG:
      *obj = ebpf_calloc(sizeof(struct ebpf_obj_prog), 1);
      if (!*obj) {
        return ENOMEM;
      }
      error = ebpf_obj_prog_ctor((struct ebpf_obj_prog *)*obj, req);
      break;
    default:
      return EINVAL;
  }

  if (error) {
    ebpf_free(*obj);
    return error;
  }

  (*obj)->obj_type = type;

  return 0;
}

void
ebpf_obj_delete(struct ebpf_obj *obj)
{
  switch (obj->obj_type) {
    case EBPF_OBJ_TYPE_PROG:
      ebpf_obj_prog_dtor((struct ebpf_obj_prog *)obj);
      break;
    default:
      return;
  }
  ebpf_free(obj);
}
