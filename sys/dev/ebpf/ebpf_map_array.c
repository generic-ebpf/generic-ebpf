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
#include "ebpf_allocator.h"

struct ebpf_map_array {
	ebpf_allocator_t allocator;
	uint64_t counter; // entry counter
	void **array;
};

static int
array_map_init_common(struct ebpf_map_array *self, uint32_t key_size,
		      uint32_t value_size, uint32_t max_entries, uint32_t flags)
{
	int error;

	self->array = ebpf_calloc(max_entries, sizeof(void *));
	if (!self->array) {
		return ENOMEM;
	}

	ebpf_allocator_init(&self->allocator, value_size, 8);

	error = ebpf_allocator_prealloc(&self->allocator, max_entries);
	if (error) {
		goto err0;
	}

	self->counter = 0;

	return 0;

err0:
	ebpf_allocator_deinit(&self->allocator);
	ebpf_free(self->array);
	return error;
}

static int
array_map_init(struct ebpf_map *self, uint32_t key_size, uint32_t value_size,
	       uint32_t max_entries, uint32_t flags)
{
	int error;

	struct ebpf_map_array *map = ebpf_malloc(sizeof(struct ebpf_map_array));
	if (!map) {
		return ENOMEM;
	}

	error = array_map_init_common(map, key_size, value_size, max_entries,
				      flags);
	if (error) {
		ebpf_free(map);
		return error;
	}

	self->data = map;

	return 0;
}

static void
array_map_deinit_common(struct ebpf_map_array *self, void *arg)
{
	ebpf_allocator_deinit(&self->allocator);
	ebpf_free(self->array);
	ebpf_free(self);
}

static void
array_map_deinit(struct ebpf_map *self, void *arg)
{
	array_map_deinit_common(self->data, arg);
}

static void *
array_map_lookup_elem_common(struct ebpf_map_array *self, uint32_t *key,
			     uint64_t flags)
{
	if (self->counter == 0) {
		return NULL;
	}

	return self->array[*key];
}

static void *
array_map_lookup_elem(struct ebpf_map *self, void *key, uint64_t flags)
{
	if (*(uint32_t *)key >= self->max_entries) {
		return NULL;
	}

	return array_map_lookup_elem_common(self->data, (uint32_t *)key, flags);
}

static int
array_map_update_elem_common(struct ebpf_map *self,
			     struct ebpf_map_array *array, void *key,
			     void *value, uint64_t flags)
{
	void *elem = array_map_lookup_elem_common(array, key, 0);
	if (elem) {
		memcpy(elem, value, self->value_size);
		goto end;
	}

	elem = ebpf_allocator_alloc(&array->allocator);
	if (!elem) {
		return ENOMEM;
	}

	memcpy(elem, value, self->value_size);
	array->array[*(uint32_t *)key] = elem;

end:
	array->counter++;
	return 0;
}

static int
array_map_update_elem(struct ebpf_map *self, void *key, void *value,
		      uint64_t flags)
{
	if (*(uint32_t *)key >= self->max_entries) {
		return EINVAL;
	}

	return array_map_update_elem_common(self, self->data, key, value,
					    flags);
}

static int
array_map_delete_elem_common(struct ebpf_map *self,
			     struct ebpf_map_array *array, uint32_t key)
{
	if (array->counter == 0) {
		return ENOENT;
	}

	if (key >= self->max_entries) {
		return EINVAL;
	}

	if (!array->array[key]) {
		return ENOENT;
	}

	ebpf_allocator_free(&array->allocator, array->array[key]);
	array->array[key] = NULL;
	array->counter--;

	return 0;
}

static int
array_map_delete_elem(struct ebpf_map *self, void *key)
{
	return array_map_delete_elem_common(self, self->data, *(uint32_t *)key);
}

static int
array_map_get_next_key(struct ebpf_map *self, void *key, void *next_key)
{
	uint32_t k = key ? *(uint32_t *)key : UINT32_MAX;
	uint32_t *nk = (uint32_t *)next_key;

	if (k >= self->max_entries) {
		*nk = 0;
		return 0;
	}

	if (k == self->max_entries - 1) {
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
