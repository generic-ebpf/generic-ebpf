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

struct ebpf_map_array {
	void *array;
};

#define map_to_array(map)                                                      \
	(uint8_t *)(((struct ebpf_map_array *)(map->data))->array)

static int
array_map_init_common(struct ebpf_map_array *array_map, uint32_t key_size,
		      uint32_t value_size, uint32_t max_entries, uint32_t flags)
{
	array_map->array = ebpf_calloc(max_entries, key_size);
	if (!array_map->array) {
		return ENOMEM;
	}

	return 0;
}

static int
array_map_init(struct ebpf_map *map, uint32_t key_size, uint32_t value_size,
	       uint32_t max_entries, uint32_t flags)
{
	int error;

	struct ebpf_map_array *array_map =
	    ebpf_calloc(1, sizeof(struct ebpf_map_array));
	if (!map) {
		return ENOMEM;
	}

	error = array_map_init_common(array_map, key_size, value_size,
				      max_entries, flags);
	if (error) {
		ebpf_free(array_map);
		return error;
	}

	map->data = array_map;

	return 0;
}

static void
array_map_deinit_common(struct ebpf_map_array *array_map, void *arg)
{
	ebpf_free(array_map->array);
	ebpf_free(array_map);
}

static void
array_map_deinit(struct ebpf_map *map, void *arg)
{
	array_map_deinit_common(map->data, arg);
}

static void *
array_map_lookup_elem(struct ebpf_map *map, void *key, uint64_t flags)
{
	if (*(uint32_t *)key >= map->max_entries) {
		return NULL;
	}

	uint8_t *array = map_to_array(map);

	return array + (map->key_size * *(uint32_t *)key);
}

static int
array_map_update_elem_common(struct ebpf_map *map, struct ebpf_map_array *array,
			     void *key, void *value, uint64_t flags)
{
	uint8_t *elem = map_to_array(map) + (map->key_size * *(uint32_t *)key);
	memcpy(elem, value, map->value_size);
	return 0;
}

static int
array_map_update_elem(struct ebpf_map *map, void *key, void *value,
		      uint64_t flags)
{
	struct ebpf_map_array *array_map = map->data;

	if (flags & EBPF_NOEXIST) {
		return EEXIST;
	}

	if (*(uint32_t *)key >= map->max_entries) {
		return EINVAL;
	}

	return array_map_update_elem_common(map, array_map, key, value, flags);
}

static int
array_map_delete_elem(struct ebpf_map *map, void *key)
{
	return EINVAL;
}

static int
array_map_get_next_key(struct ebpf_map *map, void *key, void *next_key)
{
	uint32_t k = key ? *(uint32_t *)key : UINT32_MAX;
	uint32_t *nk = (uint32_t *)next_key;

	if (k >= map->max_entries) {
		*nk = 0;
		return 0;
	}

	if (k == map->max_entries - 1) {
		return ENOENT;
	}

	*nk = k + 1;
	return 0;
}

struct ebpf_map_ops array_map_ops = {
    .init = array_map_init,
    .update_elem = array_map_update_elem,
    .lookup_elem = array_map_lookup_elem,
    .delete_elem = array_map_delete_elem,
    .get_next_key = array_map_get_next_key,
    .update_elem_from_user = array_map_update_elem,
    .lookup_elem_from_user = array_map_lookup_elem,
    .delete_elem_from_user = array_map_delete_elem,
    .get_next_key_from_user = array_map_get_next_key,
    .deinit = array_map_deinit};
