#include "ebpf_map.h"

extern struct ebpf_map_ops array_map_ops;

const struct ebpf_map_ops *ebpf_map_ops[] = {
  [EBPF_MAP_TYPE_ARRAY] = &array_map_ops
};

void*
ebpf_map_lookup_elem(struct ebpf_obj_map *self,
    void *key, uint64_t flags)
{
  if (!self || !key) {
    return NULL;
  }

  return ebpf_map_ops[self->map_type]->lookup_elem(self,
      key, flags);
}

int
ebpf_map_update_elem(struct ebpf_obj_map *self,
    void *key, void *value, uint64_t flags)
{
  if (!self || !key || !value) {
    return EINVAL;
  }

  return ebpf_map_ops[self->map_type]->update_elem(self,
      key, value, flags);
}

int
ebpf_map_delete_elem(struct ebpf_obj_map *self,
    void *key)
{
  if (!self || !key) {
    return EINVAL;
  }

  return ebpf_map_ops[self->map_type]->delete_elem(self,
      key);
}

int
ebpf_map_get_next_key(struct ebpf_obj_map *self,
    void *key, void *next_key)
{
  /*
   * key == NULL is valid, because it means "Give me a
   * first key"
   */
  if (!self || !next_key) {
    return EINVAL;
  }

  return ebpf_map_ops[self->map_type]->get_next_key(self,
      key, next_key);
}
