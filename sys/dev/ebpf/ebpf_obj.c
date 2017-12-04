#include "ebpf_obj.h"

/*
 * Destructor of ebpf program
 */
static void
ebpf_obj_prog_dtor(struct ebpf_obj *obj)
{
  struct ebpf_obj_prog *prog_obj;
  prog_obj = (struct ebpf_obj_prog *)obj;
  ebpf_free(prog_obj->prog);
  ebpf_free(prog_obj);
  ebpf_error("ebpf_obj_prog_dtor\n");
}

bool ebpf_obj_is_type(uint16_t type, struct ebpf_obj *obj)
{
  switch (type) {
    case EBPF_OBJ_TYPE_PROG:
      return obj->dtor == ebpf_obj_prog_dtor;
    default:
      return false;
  }
}

/*
 * Allocate new ebpf object. It ususally bound to struct file
 * and its life time is same as it.
 */
struct ebpf_obj*
ebpf_obj_new(uint16_t type)
{
  struct ebpf_obj *ret = NULL;

  if (type >= __EBPF_OBJ_TYPE_MAX) {
    return NULL;
  }

  switch (type) {
    case EBPF_OBJ_TYPE_PROG:
      ret = ebpf_calloc(sizeof(struct ebpf_obj_prog), 1);
      if (!ret) {
        return NULL;
      }
      ret->type = type;
      ret->dtor = ebpf_obj_prog_dtor;
      break;
    default:
      // do nothing
      break;
  }

  return ret;
}

void
ebpf_obj_delete(struct ebpf_obj *obj)
{
  obj->dtor(obj);
}
