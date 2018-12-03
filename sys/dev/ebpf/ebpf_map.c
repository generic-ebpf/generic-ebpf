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

const struct ebpf_map_type *ebpf_map_types[] = {
	[EBPF_MAP_TYPE_BAD]              = &bad_map_type,
	[EBPF_MAP_TYPE_ARRAY]            = &array_map_type,
	[EBPF_MAP_TYPE_PERCPU_ARRAY]     = &percpu_array_map_type,
	[EBPF_MAP_TYPE_HASHTABLE]        = &hashtable_map_type,
	[EBPF_MAP_TYPE_PERCPU_HASHTABLE] = &percpu_hashtable_map_type
};

#define EBPF_MAP_TYPE_OPS(_type) (ebpf_map_types[_type]->ops)

const struct ebpf_map_type *
ebpf_get_map_type(uint16_t type)
{
	if (type >= EBPF_MAP_TYPE_MAX) {
		return NULL;
	}

	return ebpf_map_types[type];
}

int
ebpf_map_init(struct ebpf_map *map, struct ebpf_map_attr *attr)
{
	int error;

	if (map == NULL || attr == NULL ||
			attr->type >= EBPF_MAP_TYPE_MAX ||
			attr->key_size == 0 || attr->value_size == 0 ||
			attr->max_entries == 0) {
		return EINVAL;
	}

	map->type = attr->type;
	map->key_size = attr->key_size;
	map->value_size = attr->value_size;
	map->max_entries = attr->max_entries;
	map->map_flags = attr->flags;
	map->deinit = ebpf_map_deinit_default;

	error = EBPF_MAP_TYPE_OPS(attr->type).init(map, attr);
	if (error != 0) {
		return error;
	}

	return 0;
}

void *
ebpf_map_lookup_elem(struct ebpf_map *map, void *key)
{
	if (map == NULL || key == NULL) {
		return NULL;
	}

	return EBPF_MAP_TYPE_OPS(map->type).lookup_elem(map, key);
}

int
ebpf_map_lookup_elem_from_user(struct ebpf_map *map, void *key, void *value)
{
	int error;

	if (map == NULL || key == NULL || value == NULL) {
		return EINVAL;
	}

	ebpf_epoch_enter();
	error = EBPF_MAP_TYPE_OPS(map->type).lookup_elem_from_user(map, key, value);
	ebpf_epoch_exit();

	return error;
}

int
ebpf_map_update_elem(struct ebpf_map *map, void *key, void *value,
		     uint64_t flags)
{
	if (map == NULL || key == NULL ||
			value == NULL || flags > EBPF_EXIST) {
		return EINVAL;
	}

	return EBPF_MAP_TYPE_OPS(map->type).update_elem(map, key, value, flags);
}

int
ebpf_map_update_elem_from_user(struct ebpf_map *map, void *key, void *value,
			       uint64_t flags)
{
	int error;

	ebpf_epoch_enter();
	error = EBPF_MAP_TYPE_OPS(map->type).update_elem_from_user(map, key, value, flags);
	ebpf_epoch_exit();

	return error;
}

int
ebpf_map_delete_elem(struct ebpf_map *map, void *key)
{
	if (map == NULL || key == NULL) {
		return EINVAL;
	}

	return EBPF_MAP_TYPE_OPS(map->type).delete_elem(map, key);
}

int
ebpf_map_delete_elem_from_user(struct ebpf_map *map, void *key)
{
	int error;
	if (map == NULL || key == NULL) {
		return EINVAL;
	}

	ebpf_epoch_enter();
	error = EBPF_MAP_TYPE_OPS(map->type).delete_elem_from_user(map, key);
	ebpf_epoch_exit();

	return error;
}

int
ebpf_map_get_next_key_from_user(struct ebpf_map *map, void *key, void *next_key)
{
	int error;

	/*
	 * key == NULL is valid, because it means "Give me a
	 * first key"
	 */
	if (map == NULL || next_key == NULL) {
		return EINVAL;
	}

	ebpf_epoch_enter();
	error = EBPF_MAP_TYPE_OPS(map->type).get_next_key_from_user(map, key, next_key);
	ebpf_epoch_exit();

	return error;
}

void
ebpf_map_deinit_default(struct ebpf_map *map, void *arg)
{
	EBPF_MAP_TYPE_OPS(map->type).deinit(map, arg);
}

void
ebpf_map_deinit(struct ebpf_map *map, void *arg)
{
	if (map == NULL) {
		return;
	}

	if (map->deinit != NULL) {
		map->deinit(map, arg);
	}
}
