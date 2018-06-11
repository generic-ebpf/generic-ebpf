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
#include "ebpf_allocator.h"

struct ebpf_map_array {
	ebpf_rwlock_t rw;
	ebpf_allocator_t allocator;
	uint64_t counter; // entry counter
	void **array;
};

static int
array_map_init_common(struct ebpf_map_array *array_map, uint32_t key_size,
		      uint32_t value_size, uint32_t max_entries, uint32_t flags)
{
	int error;

	array_map->array = ebpf_calloc(max_entries, sizeof(void *));
	if (!array_map->array) {
		return ENOMEM;
	}

	ebpf_rw_init(&array_map->rw, "ebpf_array_map_lock");
	ebpf_allocator_init(&array_map->allocator, value_size, 8);

	error = ebpf_allocator_prealloc(&array_map->allocator, max_entries);
	if (error) {
		goto err0;
	}

	array_map->counter = 0;

	return 0;

err0:
	ebpf_allocator_deinit(&array_map->allocator);
	ebpf_free(array_map->array);
	return error;
}

static int
array_map_init(struct ebpf_map *map, uint32_t key_size, uint32_t value_size,
	       uint32_t max_entries, uint32_t flags)
{
	int error;

	struct ebpf_map_array *array_map = ebpf_calloc(1, sizeof(struct ebpf_map_array));
	if (!map) {
		return ENOMEM;
	}

	error = array_map_init_common(array_map, key_size, value_size, max_entries,
				      flags);
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
	ebpf_rw_destroy(&array_map->rw);
	ebpf_allocator_deinit(&array_map->allocator);
	ebpf_free(array_map->array);
	ebpf_free(array_map);
}

static void
array_map_deinit(struct ebpf_map *map, void *arg)
{
	array_map_deinit_common(map->data, arg);
}

static void *
array_map_lookup_elem_common(struct ebpf_map_array *array_map, uint32_t *key,
			     uint64_t flags)
{
	if (array_map->counter == 0) {
		return NULL;
	}

	return array_map->array[*key];
}

static void *
array_map_lookup_elem(struct ebpf_map *map, void *key, uint64_t flags)
{
	if (*(uint32_t *)key >= map->max_entries) {
		return NULL;
	}

	void *ret;
	struct ebpf_map_array *array_map = map->data;

	ebpf_rw_rlock(&array_map->rw);
	ret = array_map_lookup_elem_common(array_map, (uint32_t *)key, flags);
	ebpf_rw_runlock(&array_map->rw);

	return ret;
}

static int
array_map_update_elem_common(struct ebpf_map *map,
			     struct ebpf_map_array *array, void *key,
			     void *value, uint64_t flags)
{
	void *elem = array_map_lookup_elem_common(array, key, 0);
	if (elem) {
		if (flags & EBPF_NOEXIST) {
			return EEXIST;
		} else {
			memcpy(elem, value, map->value_size);
			goto end;
		}
	}

	if (flags & EBPF_EXIST) {
		return ENOENT;
	}

	elem = ebpf_allocator_alloc(&array->allocator);
	if (!elem) {
		return ENOMEM;
	}

	memcpy(elem, value, map->value_size);
	array->array[*(uint32_t *)key] = elem;

end:
	array->counter++;
	return 0;
}

static int
array_map_update_elem(struct ebpf_map *map, void *key, void *value,
		      uint64_t flags)
{
	int ret;
	struct ebpf_map_array *array_map = map->data;

	if (*(uint32_t *)key >= map->max_entries) {
		return EINVAL;
	}

	ebpf_rw_wlock(&array_map->rw);
	ret = array_map_update_elem_common(map, array_map, key, value, flags);
	ebpf_rw_wunlock(&array_map->rw);

	return ret;
}

static int
array_map_delete_elem_common(struct ebpf_map *map,
			     struct ebpf_map_array *array_map, uint32_t key)
{
	if (array_map->counter == 0) {
		return ENOENT;
	}

	if (key >= map->max_entries) {
		return EINVAL;
	}

	if (!array_map->array[key]) {
		return ENOENT;
	}

	ebpf_allocator_free(&array_map->allocator, array_map->array[key]);
	array_map->array[key] = NULL;
	array_map->counter--;

	return 0;
}

static int
array_map_delete_elem(struct ebpf_map *map, void *key)
{
	int ret;
	struct ebpf_map_array *array_map = map->data;

	ebpf_rw_wlock(&array_map->rw);
	ret = array_map_delete_elem_common(map, array_map, *(uint32_t *)key);
	ebpf_rw_wunlock(&array_map->rw);

	return ret;
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
