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

#pragma once

#include "ebpf_obj.h"

typedef int ebpf_map_create_t(struct ebpf_obj_map *self, uint16_t key_size,
                              uint16_t value_size, uint16_t max_entries,
                              uint32_t flags);
typedef void *ebpf_map_lookup_elem_t(struct ebpf_obj_map *self, void *key,
                                     uint64_t flags);
typedef int ebpf_map_update_elem_t(struct ebpf_obj_map *self, void *key,
                                   void *value, uint64_t flags);
typedef int ebpf_map_delete_elem_t(struct ebpf_obj_map *self, void *key);
typedef int ebpf_map_get_next_key_t(struct ebpf_obj_map *self, void *key,
                                    void *next_key);
typedef void ebpf_map_destroy_t(struct ebpf_obj_map *self);

struct ebpf_map_ops {
    ebpf_map_create_t *create;
    ebpf_map_lookup_elem_t *lookup_elem;
    ebpf_map_update_elem_t *update_elem;
    ebpf_map_delete_elem_t *delete_elem;
    ebpf_map_get_next_key_t *get_next_key;
    ebpf_map_destroy_t *destroy;
};

extern const struct ebpf_map_ops *ebpf_map_ops[];

extern void *ebpf_map_lookup_elem(struct ebpf_obj_map *self, void *key,
                                  uint64_t flags);
extern int ebpf_map_update_elem(struct ebpf_obj_map *self, void *key,
                                void *value, uint64_t flags);
extern int ebpf_map_delete_elem(struct ebpf_obj_map *self, void *key);
extern int ebpf_map_get_next_key(struct ebpf_obj_map *self, void *key,
                                 void *next_key);
