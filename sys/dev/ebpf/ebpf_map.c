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

static struct ebpf_obj_type_registry map_type_registry;

int
ebpf_register_map_type(struct ebpf_map_type *type, uint16_t *idxp)
{
	return ebpf_obj_type_register(&map_type_registry,
			(struct ebpf_obj_type *)type, idxp);
}

int
ebpf_unregister_map_type(uint16_t idx)
{
	return ebpf_obj_type_unregister(&map_type_registry, idx);
}

int
ebpf_acquire_map_type(uint16_t idx, struct ebpf_map_type **typep)
{
	return ebpf_obj_type_acquire(&map_type_registry, idx,
			(struct ebpf_obj_type **)typep);
}

int
ebpf_release_map_type(struct ebpf_map_type *type)
{
	return ebpf_obj_type_release((struct ebpf_obj_type *)type);
}

static void
register_basic_map(struct ebpf_map_type *type, uint16_t *idxp, uint16_t expect)
{
	int error;

	ebpf_refcount_init(&type->emt_type.eot_refcount, 0);

	error = ebpf_register_map_type(type, idxp);
	if (error != 0) {
		return error;
	}
	
	ebpf_assert(error == 0 && *idxp == expect);
}

static void
unregister_basic_map(uint16_t idx)
{
	int error;
	error = ebpf_unregister_map_type(idx);
	ebpf_assert(error == 0);
}

static bool
map_type_is_used(struct ebpf_map_type *type)
{
	return type->emt_type.eot_refcount != 0;
}

int
ebpf_init_map_types(void)
{
	int error;
	uint16_t idx;

	error = ebpf_obj_type_registry_init(&map_type_registry);
	if (error != 0) {
		return error;
	}

	/*
	 * Register basic map types
	 */
	register_basic_map(&bad_map_type, &idx, EBPF_MAP_TYPE_BAD);
	register_basic_map(&array_map_type, &idx, EBPF_MAP_TYPE_ARRAY);
	register_basic_map(&percpu_array_map_type, &idx, EBPF_MAP_TYPE_PERCPU_ARRAY);
	register_basic_map(&hashtable_map_type, &idx, EBPF_MAP_TYPE_HASHTABLE);
	register_basic_map(&percpu_hashtable_map_type, &idx, EBPF_MAP_TYPE_PERCPU_HASHTABLE);
}

int
ebpf_deinit_map_types(void)
{
	static bool basic_map_unregistered = false;

	if (basic_map_unregistered == false) {
		unregister_basic_map(EBPF_MAP_TYPE_BAD);
		unregister_basic_map(EBPF_MAP_TYPE_ARRAY);
		unregister_basic_map(EBPF_MAP_TYPE_PERCPU_ARRAY);
		unregister_basic_map(EBPF_MAP_TYPE_HASHTABLE);
		unregister_basic_map(EBPF_MAP_TYPE_PERCPU_HASHTABLE);
		basic_map_unregistered = true;
	}

	if (map_type_is_used(&bad_map_type) ||
			map_type_is_used(&array_map_type) ||
			map_type_is_used(&percpu_array_map_type) ||
			map_type_is_used(&hashtable_map_type) ||
			map_type_is_used(&percpu_hashtable_map_type)) {
		return EBUSY;
	}

	return 0;
}

int
ebpf_map_init(struct ebpf_map *map, uint16_t type, uint32_t key_size,
	      uint32_t value_size, uint32_t max_entries, uint32_t flags)
{
	int error;

	if (!map || type >= __EBPF_MAP_TYPE_MAX || !key_size || !value_size ||
	    !max_entries) {
		return EINVAL;
	}

	error = ebpf_acquire_map_type(type, &map->type);
	if (error) {
		return error;
	}

	map->key_size = key_size;
	map->value_size = value_size;
	map->max_entries = max_entries;
	map->map_flags = flags;
	map->deinit = ebpf_map_deinit_default;

	error = map->type->ops.init(map, key_size, value_size,
					 max_entries, flags);
	if (error) {
		return error;
	}

	return 0;
}

void *
ebpf_map_lookup_elem(struct ebpf_map *map, void *key)
{
	if (!map || !key) {
		return NULL;
	}

	return map->type->ops.lookup_elem(map, key);
}

int
ebpf_map_lookup_elem_from_user(struct ebpf_map *map, void *key, void *value)
{
	int error;

	if (!map || !key || !value) {
		return EINVAL;
	}

	ebpf_epoch_enter();
	error = map->type->ops.lookup_elem_from_user(map, key, value);
	ebpf_epoch_exit();

	return error;
}

int
ebpf_map_update_elem(struct ebpf_map *map, void *key, void *value,
		     uint64_t flags)
{
	if (!map || !key || !value || flags > EBPF_EXIST) {
		return EINVAL;
	}

	return map->type->ops.update_elem(map, key, value, flags);
}

int
ebpf_map_update_elem_from_user(struct ebpf_map *map, void *key, void *value,
			       uint64_t flags)
{
	int error;

	ebpf_epoch_enter();
	error = map->type->ops.update_elem_from_user(map, key, value, flags);
	ebpf_epoch_exit();

	return error;
}

int
ebpf_map_delete_elem(struct ebpf_map *map, void *key)
{
	if (!map || !key) {
		return EINVAL;
	}

	return map->type->ops.delete_elem(map, key);
}

int
ebpf_map_delete_elem_from_user(struct ebpf_map *map, void *key)
{
	int error;
	if (!map || !key) {
		return EINVAL;
	}

	ebpf_epoch_enter();
	error = map->type->ops.delete_elem_from_user(map, key);
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
	if (!map || !next_key) {
		return EINVAL;
	}

	ebpf_epoch_enter();
	error = map->type->ops.get_next_key_from_user(map, key, next_key);
	ebpf_epoch_exit();

	return error;
}

void
ebpf_map_deinit_default(struct ebpf_map *map, void *arg)
{
	int error;
	map->type->ops.deinit(map, arg);
	error = ebpf_release_map_type(map->type);
	ebpf_assert(error == 0);
}

void
ebpf_map_deinit(struct ebpf_map *map, void *arg)
{
	if (!map) {
		return;
	}

	if (map->deinit) {
		map->deinit(map, arg);
	}
}
