/*
 * Copyright 2017 Yutaro Hayakawa
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "ebpf_map.h"

extern struct ebpf_map_ops array_map_ops;
extern struct ebpf_map_ops tommyhashtbl_map_ops;

const struct ebpf_map_ops *ebpf_map_ops[] = {[EBPF_MAP_TYPE_ARRAY] =
                                                 &array_map_ops,
                                             [EBPF_MAP_TYPE_TOMMYHASHTBL] =
                                                 &tommyhashtbl_map_ops};

int
ebpf_map_init(struct ebpf_map *mapp, uint16_t type, uint16_t key_size,
              uint16_t value_size, uint32_t max_entries, uint32_t flags)
{
    int error;

    if (!mapp || type >= __EBPF_MAP_TYPE_MAX || !key_size || !value_size ||
        !max_entries) {
        return EINVAL;
    }

    error = ebpf_map_ops[type]->init(mapp, key_size, value_size, max_entries,
                                     flags);
    if (error) {
        return error;
    }

    mapp->key_size = key_size;
    mapp->value_size = value_size;
    mapp->max_entries = max_entries;
    mapp->map_flags = flags;
    mapp->deinit = ebpf_map_deinit_default;

    return 0;
}

void *
ebpf_map_lookup_elem(struct ebpf_map *self, void *key, uint64_t flags)
{
    if (!self || !key) {
        return NULL;
    }

    if (ebpf_map_ops[self->type]->lookup_elem) {
        return ebpf_map_ops[self->type]->lookup_elem(self, key, flags);
    } else {
        return NULL;
    }
}

int
ebpf_map_update_elem(struct ebpf_map *self, void *key, void *value,
                     uint64_t flags)
{
    if (!self || !key || !value) {
        return EINVAL;
    }

    if (ebpf_map_ops[self->type]->update_elem) {
        return ebpf_map_ops[self->type]->update_elem(self, key, value, flags);
    } else {
        return ENOTSUP;
    }
}

int
ebpf_map_delete_elem(struct ebpf_map *self, void *key)
{
    if (!self || !key) {
        return EINVAL;
    }

    if (ebpf_map_ops[self->type]->delete_elem) {
        return ebpf_map_ops[self->type]->delete_elem(self, key);
    } else {
        return ENOTSUP;
    }
}

int
ebpf_map_get_next_key(struct ebpf_map *self, void *key, void *next_key)
{
    /*
     * key == NULL is valid, because it means "Give me a
     * first key"
     */
    if (!self || !next_key) {
        return EINVAL;
    }

    if (ebpf_map_ops[self->type]->get_next_key) {
        return ebpf_map_ops[self->type]->get_next_key(self, key, next_key);
    } else {
        return ENOTSUP;
    }
}

void
ebpf_map_deinit_default(struct ebpf_map *self, void *arg)
{
    ebpf_map_ops[self->type]->deinit(self, arg);
}

void
ebpf_map_deinit(struct ebpf_map *self, void *arg)
{
    if (!self) {
        return;
    }
    self->deinit(self, arg);
}
