/*-
 * SPDX-License-Identifier: Apache License 2.0
 *
 * Copyright 2017-2018 Yutaro Hayakawa
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

#include <sys/ebpf_obj.h>
#include <sys/ebpf.h>

struct ebpf_map;

struct ebpf_map_attr {
	uint16_t type;
	uint32_t key_size;
	uint32_t value_size;
	uint32_t max_entries;
	uint32_t flags;
};

typedef int ebpf_map_init_t(struct ebpf_map *em, struct ebpf_map_attr *attr);
typedef void *ebpf_map_lookup_elem_t(struct ebpf_map *em, void *key);
typedef int ebpf_map_lookup_elem_from_user_t(struct ebpf_map *em, void *key,
					     void *value);
typedef int ebpf_map_update_elem_t(struct ebpf_map *em, void *key, void *value,
				   uint64_t flags);
typedef int ebpf_map_delete_elem_t(struct ebpf_map *em, void *key);
typedef int ebpf_map_get_next_key_t(struct ebpf_map *em, void *key,
				    void *next_key);
typedef void ebpf_map_deinit_t(struct ebpf_map *em);

struct ebpf_map_ops {
	ebpf_map_init_t *init;
	ebpf_map_lookup_elem_t *lookup_elem;
	ebpf_map_update_elem_t *update_elem;
	ebpf_map_delete_elem_t *delete_elem;
	ebpf_map_lookup_elem_from_user_t *lookup_elem_from_user;
	ebpf_map_update_elem_t *update_elem_from_user;
	ebpf_map_delete_elem_t *delete_elem_from_user;
	ebpf_map_get_next_key_t *get_next_key_from_user;
	ebpf_map_deinit_t *deinit;
};

struct ebpf_map_type {
	char name[EBPF_NAME_MAX];
	struct ebpf_map_ops ops;
};

struct ebpf_map {
	struct ebpf_obj eo;
	uint16_t type;
	uint32_t key_size;
	uint32_t value_size;
	uint32_t map_flags;
	uint32_t max_entries;
	bool percpu;
	void *data;
};

#define EO2EM(eo) \
	(eo != NULL && eo->eo_type == EBPF_OBJ_TYPE_MAP ? \
   (struct ebpf_map *)eo : NULL)

const struct ebpf_map_type *ebpf_get_map_type(uint16_t type);
int ebpf_map_create(struct ebpf_map **emp, struct ebpf_map_attr *attr);
void *ebpf_map_lookup_elem(struct ebpf_map *em, void *key);
int ebpf_map_update_elem(struct ebpf_map *em, void *key, void *value,
			 uint64_t flags);
int ebpf_map_delete_elem(struct ebpf_map *em, void *key);
int ebpf_map_lookup_elem_from_user(struct ebpf_map *em, void *key,
				   void *value);
int ebpf_map_update_elem_from_user(struct ebpf_map *em, void *key, void *value,
				   uint64_t flags);
int ebpf_map_delete_elem_from_user(struct ebpf_map *em, void *key);
int ebpf_map_get_next_key_from_user(struct ebpf_map *em, void *key,
				    void *next_key);
void ebpf_map_destroy(struct ebpf_map *em);
