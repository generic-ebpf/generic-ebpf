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

const struct ebpf_map_ops *ebpf_map_ops[] = {[EBPF_MAP_TYPE_ARRAY] =
                                                 &array_map_ops};

void *
ebpf_map_lookup_elem(struct ebpf_obj_map *self, void *key, uint64_t flags)
{
    if (!self || !key) {
        return NULL;
    }

    return ebpf_map_ops[self->map_type]->lookup_elem(self, key, flags);
}

int
ebpf_map_update_elem(struct ebpf_obj_map *self, void *key, void *value,
                     uint64_t flags)
{
    if (!self || !key || !value) {
        return EINVAL;
    }

    return ebpf_map_ops[self->map_type]->update_elem(self, key, value, flags);
}

int
ebpf_map_delete_elem(struct ebpf_obj_map *self, void *key)
{
    if (!self || !key) {
        return EINVAL;
    }

    return ebpf_map_ops[self->map_type]->delete_elem(self, key);
}

int
ebpf_map_get_next_key(struct ebpf_obj_map *self, void *key, void *next_key)
{
    /*
     * key == NULL is valid, because it means "Give me a
     * first key"
     */
    if (!self || !next_key) {
        return EINVAL;
    }

    return ebpf_map_ops[self->map_type]->get_next_key(self, key, next_key);
}
