#include "ebpf_kern.h"
#include "ebpf_map.h"

struct ebpf_map_null {
  uint64_t counter; // entry counter
};

static int
null_map_create(struct ebpf_obj_map *self, uint16_t key_size,
    uint16_t value_size, uint16_t max_entries, uint32_t flags)
{
  self->map_type = EBPF_MAP_TYPE_NULL;
  self->key_size = key_size;
  self->value_size = value_size;
  self->max_entries = max_entries;
  self->map_flags = flags;
  self->data = ebpf_calloc(sizeof(struct ebpf_map_null), 1);
  if (!self->data) {
    return ENOMEM;
  }
  return 0;
}

static int
null_map_update_elem(struct ebpf_obj_map *self, void *key, void *value,
    uint64_t flags)
{
  struct ebpf_map_null *map = (struct ebpf_map_null *)self->data;

  if (map->counter == self->max_entries - 1) {
    return EBUSY;
  }

  map->counter++;

  return 0;
}

static int
null_map_lookup_elem(struct ebpf_obj_map *self, void *key, void *value, uint64_t flags)
{
  struct ebpf_map_null *map = (struct ebpf_map_null *)self->data;

  if (map->counter == 0) {
    return ENOENT;
  }

  int error;
  uint8_t *tmp = ebpf_calloc(self->value_size, 1);
  if (!tmp) {
    return ENOENT;
  }

  error = ebpf_copyout(tmp, value, self->value_size);
  if (error) {
    ebpf_free(tmp);
    return EIO;
  }

  ebpf_free(tmp);

  return 0;
}

static int
null_map_delete_elem(struct ebpf_obj_map *self, void *key)
{
  struct ebpf_map_null *map = (struct ebpf_map_null *)self->data;

  if (map->counter == 0) {
    return ENOENT;
  }

  map->counter--;

  return 0;
}

static int
null_map_get_next_key(struct ebpf_obj_map *self, void *key, void *next_key)
{
  struct ebpf_map_null *map = (struct ebpf_map_null *)self->data;

  if (map->counter == 0) {
    return ENOENT;
  }

  int error;
  uint8_t *tmp = ebpf_calloc(self->key_size, 1);
  if (!tmp) {
    return ENOENT;
  }

  error = ebpf_copyout(tmp, next_key, self->key_size);
  if (error) {
    ebpf_free(tmp);
    return EIO;
  }

  ebpf_free(tmp);

  return 0;
}

static void
null_map_destroy(struct ebpf_obj_map *self)
{
  ebpf_free(self->data);
}

const struct ebpf_map_ops null_map_ops = {
  .create         = null_map_create,
  .update_elem    = null_map_update_elem,
  .lookup_elem    = null_map_lookup_elem,
  .delete_elem    = null_map_delete_elem,
  .get_next_key   = null_map_get_next_key,
  .destroy        = null_map_destroy
};
