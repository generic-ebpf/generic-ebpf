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

#include "ebpf_platform.h"
#include <sys/ebpf.h>

struct ebpf_map;

typedef int ebpf_map_init_t(struct ebpf_map *self, uint32_t key_size,
			    uint32_t value_size, uint32_t max_entries,
			    uint32_t flags);
typedef void *ebpf_map_lookup_elem_t(struct ebpf_map *self, void *key,
				     uint64_t flags);
typedef int ebpf_map_update_elem_t(struct ebpf_map *self, void *key,
				   void *value, uint64_t flags);
typedef int ebpf_map_delete_elem_t(struct ebpf_map *self, void *key);
typedef int ebpf_map_get_next_key_t(struct ebpf_map *self, void *key,
				    void *next_key);
typedef void ebpf_map_deinit_t(struct ebpf_map *self, void *arg);

struct ebpf_map_ops {
	ebpf_map_init_t *init;
	ebpf_map_lookup_elem_t *lookup_elem;
	ebpf_map_update_elem_t *update_elem;
	ebpf_map_delete_elem_t *delete_elem;
	ebpf_map_get_next_key_t *get_next_key;
	ebpf_map_lookup_elem_t *lookup_elem_from_user;
	ebpf_map_update_elem_t *update_elem_from_user;
	ebpf_map_delete_elem_t *delete_elem_from_user;
	ebpf_map_get_next_key_t *get_next_key_from_user;
	ebpf_map_deinit_t *deinit;
};

struct ebpf_map {
	uint16_t type;
	uint32_t key_size;
	uint32_t value_size;
	uint32_t map_flags;
	uint32_t max_entries;
	void *data;
	void (*deinit)(struct ebpf_map *, void *);
};

void ebpf_register_map_type(uint16_t id, struct ebpf_map_ops *ops);
int ebpf_map_init(struct ebpf_map *mapp, uint16_t type, uint32_t key_size,
		  uint32_t value_size, uint32_t max_entries,
		  uint32_t map_flags);
void *ebpf_map_lookup_elem(struct ebpf_map *self, void *key, uint64_t flags);
int ebpf_map_update_elem(struct ebpf_map *self, void *key, void *value,
			 uint64_t flags);
int ebpf_map_delete_elem(struct ebpf_map *self, void *key);
int ebpf_map_get_next_key(struct ebpf_map *self, void *key, void *next_key);
void *ebpf_map_lookup_elem_from_user(struct ebpf_map *self, void *key,
				     uint64_t flags);
int ebpf_map_update_elem_from_user(struct ebpf_map *self, void *key,
				   void *value, uint64_t flags);
int ebpf_map_delete_elem_from_user(struct ebpf_map *self, void *key);
int ebpf_map_get_next_key_from_user(struct ebpf_map *self, void *key,
				    void *next_key);

/*
 * Users can extend (make subclass of) struct ebpf_map, so the destructor of
 * struct ebpf_map might be
 * overwritten. ebpf_map_deinit just calls map_object->dtor and its default
 * value is
 * ebpf_map_deinit_default. This is useful for managing external reference count
 * or locking etc.
 */
void ebpf_map_deinit(struct ebpf_map *mapp, void *arg);
void ebpf_map_deinit_default(struct ebpf_map *mapp, void *arg);
