#include "ebpf_map.h"

struct ebpf_map_array {
    uint64_t counter; // entry counter
    void **array;
};

static int
array_map_create(struct ebpf_obj_map *self, uint16_t key_size,
                 uint16_t value_size, uint16_t max_entries, uint32_t flags)
{
    if (key_size != sizeof(uint32_t)) {
        return EINVAL;
    }

    self->map_type = EBPF_MAP_TYPE_ARRAY;
    self->key_size = key_size;
    self->value_size = value_size;
    self->max_entries = max_entries;
    self->map_flags = flags;

    struct ebpf_map_array *new = ebpf_calloc(sizeof(struct ebpf_map_array), 1);
    if (!new) {
        return ENOMEM;
    }

    new->array = ebpf_calloc(sizeof(void *), self->max_entries);
    if (!new->array) {
        ebpf_free(new);
        return ENOMEM;
    }

    self->data = new;

    return 0;
}

static int
array_map_update_elem(struct ebpf_obj_map *self, void *key, void *value,
                      uint64_t flags)
{
    struct ebpf_map_array *map = (struct ebpf_map_array *)self->data;

    if (map->counter == self->max_entries - 1) {
        return EBUSY;
    }

    uint32_t *k = (uint32_t *)key;
    if (*k >= self->max_entries) {
        return EINVAL;
    }

    void *v = ebpf_calloc(self->value_size, 1);
    if (!v) {
        return ENOMEM;
    }

    if (map->array[*k]) {
        ebpf_free(map->array[*k]);
    }

    memcpy(v, value, self->value_size);

    map->array[*k] = v;
    map->counter++;

    return 0;
}

static void *
array_map_lookup_elem(struct ebpf_obj_map *self, void *key, uint64_t flags)
{
    struct ebpf_map_array *map = (struct ebpf_map_array *)self->data;

    if (map->counter == 0) {
        return NULL;
    }

    uint32_t *k = (uint32_t *)key;
    if (*k >= self->max_entries) {
        return NULL;
    }

    return map->array[*k];
}

static int
array_map_delete_elem(struct ebpf_obj_map *self, void *key)
{
    struct ebpf_map_array *map = (struct ebpf_map_array *)self->data;

    if (map->counter == 0) {
        return ENOENT;
    }

    uint32_t *k = (uint32_t *)key;
    if (*k >= self->max_entries) {
        return EINVAL;
    }

    if (!map->array[*k]) {
        return ENOENT;
    }

    ebpf_free(map->array[*k]);
    map->array[*k] = NULL;
    map->counter--;

    return 0;
}

static int
array_map_get_next_key(struct ebpf_obj_map *self, void *key, void *next_key)
{
    struct ebpf_map_array *map = (struct ebpf_map_array *)self->data;
    uint32_t *nk = (uint32_t *)next_key;
    uint32_t cur, end;

    if (key == NULL || *(uint32_t *)key == self->max_entries) {
        cur = 0;
        end = self->max_entries;
    } else if (*(uint32_t *)key > self->max_entries) {
        return EINVAL;
    } else {
        cur = (*(uint32_t *)key) + 1;
        end = *(uint32_t *)key;
    }

    do {
        if (map->array[cur]) {
            *nk = cur;
            return 0;
        }

        if (cur == self->max_entries) {
            cur = 0;
        } else {
            cur++;
        }
    } while (cur != end);

    return ENOENT;
}

static void
array_map_destroy(struct ebpf_obj_map *self)
{
    struct ebpf_map_array *map = (struct ebpf_map_array *)self->data;

    for (int i = 0; i < self->max_entries; i++) {
        if (map->array[i]) {
            ebpf_free(map->array[i]);
        }
    }

    ebpf_free(map->array);
    ebpf_free(map);
}

const struct ebpf_map_ops array_map_ops = {.create = array_map_create,
                                           .update_elem = array_map_update_elem,
                                           .lookup_elem = array_map_lookup_elem,
                                           .delete_elem = array_map_delete_elem,
                                           .get_next_key =
                                               array_map_get_next_key,
                                           .destroy = array_map_destroy};