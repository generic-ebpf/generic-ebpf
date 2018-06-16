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

#include "ebpf_map.h"

struct ebpf_map_ops *ebpf_map_ops[__EBPF_MAP_TYPE_MAX];

void
ebpf_register_map_type(uint16_t id, struct ebpf_map_ops *ops)
{
	if (id < __EBPF_MAP_TYPE_MAX && ops) {
		ebpf_map_ops[id] = ops;
	}
}

int
ebpf_map_init(struct ebpf_map *mapp, uint16_t type, uint32_t key_size,
	      uint32_t value_size, uint32_t max_entries, uint32_t flags)
{
	int error;

	if (!mapp || type >= __EBPF_MAP_TYPE_MAX || !key_size || !value_size ||
	    !max_entries) {
		return EINVAL;
	}

	mapp->type = type;
	mapp->key_size = key_size;
	mapp->value_size = value_size;
	mapp->max_entries = max_entries;
	mapp->map_flags = flags;
	mapp->deinit = ebpf_map_deinit_default;

	error = ebpf_map_ops[type]->init(mapp, key_size, value_size,
					 max_entries, flags);
	if (error) {
		return error;
	}

	return 0;
}

void *
ebpf_map_lookup_elem(struct ebpf_map *map, void *key, uint64_t flags)
{
	if (!map || !key) {
		return NULL;
	}

	return ebpf_map_ops[map->type]->lookup_elem(map, key, flags);
}

void *
ebpf_map_lookup_elem_from_user(struct ebpf_map *map, void *key, uint64_t flags)
{
	if (!map || !key) {
		return NULL;
	}

	return ebpf_map_ops[map->type]->lookup_elem_from_user(map, key, flags);
}

int
ebpf_map_update_elem(struct ebpf_map *map, void *key, void *value,
		     uint64_t flags)
{
	if (!map || !key || !value || flags > EBPF_EXIST) {
		return EINVAL;
	}

	return ebpf_map_ops[map->type]->update_elem(map, key, value, flags);
}

int
ebpf_map_update_elem_from_user(struct ebpf_map *map, void *key, void *value,
			       uint64_t flags)
{
	return ebpf_map_ops[map->type]->update_elem_from_user(map, key, value, flags);
}

int
ebpf_map_delete_elem(struct ebpf_map *map, void *key)
{
	if (!map || !key) {
		return EINVAL;
	}

	return ebpf_map_ops[map->type]->delete_elem(map, key);
}

int
ebpf_map_delete_elem_from_user(struct ebpf_map *map, void *key)
{
	if (!map || !key) {
		return EINVAL;
	}

	return ebpf_map_ops[map->type]->delete_elem_from_user(map, key);
}

int
ebpf_map_get_next_key_from_user(struct ebpf_map *map, void *key, void *next_key)
{
	/*
	 * key == NULL is valid, because it means "Give me a
	 * first key"
	 */
	if (!map || !next_key) {
		return EINVAL;
	}

	if (ebpf_map_ops[map->type]->get_next_key_from_user) {
		return ebpf_map_ops[map->type]->get_next_key_from_user(
		    map, key, next_key);
	} else {
		return ENOTSUP;
	}
}

void
ebpf_map_deinit_default(struct ebpf_map *map, void *arg)
{
	ebpf_map_ops[map->type]->deinit(map, arg);
}

void
ebpf_map_deinit(struct ebpf_map *map, void *arg)
{
	if (!map) {
		return;
	}
	map->deinit(map, arg);
}
