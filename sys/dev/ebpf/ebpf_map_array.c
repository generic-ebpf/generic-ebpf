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

struct ebpf_map_array {
	uint64_t counter; // entry counter
	void **array;
};

static int
array_map_alloc(struct ebpf_map_array **array_mapp, uint16_t max_entries)
{
	*array_mapp = ebpf_malloc(sizeof(struct ebpf_map_array));
	if (!*array_mapp) {
		return ENOMEM;
	}

	(*array_mapp)->counter = 0;
	(*array_mapp)->array = ebpf_calloc(max_entries, sizeof(void *));
	if (!(*array_mapp)->array) {
		ebpf_free(*array_mapp);
		return ENOMEM;
	}

	return 0;
}

static int
array_map_init_common(struct ebpf_map *self, uint16_t num_maps,
		      uint16_t key_size, uint16_t value_size,
		      uint16_t max_entries, uint32_t flags)
{
	int error;
	struct ebpf_map_array *cur; // only used in error handling

	if (key_size != sizeof(uint32_t)) {
		return EINVAL;
	}

	struct ebpf_map_array **new =
	    ebpf_calloc(num_maps, sizeof(struct ebpf_map_array *));
	if (!new) {
		return ENOMEM;
	}

	uint16_t i;
	for (i = 0; i < num_maps; i++) {
		error = array_map_alloc(new + i, max_entries);
		if (error) {
			goto err;
		}
	}

	self->data = new;

	return 0;

err:
	for (uint16_t j = i; j > 0; j--) {
		cur = new[j];
		ebpf_free(cur->array);
		ebpf_free(cur);
	}
	ebpf_free(new);
	return error;
}

static int
array_map_init(struct ebpf_map *self, uint16_t key_size, uint16_t value_size,
	       uint16_t max_entries, uint32_t flags)
{
	return array_map_init_common(self, 1, key_size, value_size, max_entries,
				     flags);
}

static int
array_map_init_percpu(struct ebpf_map *self, uint16_t key_size,
		      uint16_t value_size, uint16_t max_entries, uint32_t flags)
{
	return array_map_init_common(self, ebpf_ncpus(), key_size, value_size,
				     max_entries, flags);
}

static int
array_map_update_elem_common(struct ebpf_map *self, uint16_t idx, void *key,
			     void *value, uint64_t flags)
{
	struct ebpf_map_array **maps = (struct ebpf_map_array **)self->data;
	struct ebpf_map_array *map = maps[idx];

	if (map->counter == self->max_entries) {
		return EBUSY;
	}

	uint32_t *k = (uint32_t *)key;
	if (*k >= self->max_entries) {
		return EINVAL;
	}

	void *v = ebpf_calloc(self->value_size, 1);
	if (!v) {
		return ENOMEM;
	}

	if (map->array[*k]) {
		ebpf_free(map->array[*k]);
	}

	memcpy(v, value, self->value_size);

	map->array[*k] = v;
	map->counter++;

	return 0;
}

static int
array_map_update_elem(struct ebpf_map *self, void *key, void *value,
		      uint64_t flags)
{
	return array_map_update_elem_common(self, 0, key, value, flags);
}

static int
array_map_update_elem_percpu(struct ebpf_map *self, void *key, void *value,
			     uint64_t flags)
{
	return array_map_update_elem_common(self, ebpf_curcpu(), key, value,
					    flags);
}

static void *
array_map_lookup_elem_common(struct ebpf_map *self, uint16_t idx, void *key,
			     uint64_t flags)
{
	struct ebpf_map_array **maps = (struct ebpf_map_array **)self->data;
	struct ebpf_map_array *map = maps[idx];

	if (map->counter == 0) {
		return NULL;
	}

	uint32_t *k = (uint32_t *)key;
	if (*k >= self->max_entries) {
		return NULL;
	}

	return map->array[*k];
}

static void *
array_map_lookup_elem(struct ebpf_map *self, void *key, uint64_t flags)
{
	return array_map_lookup_elem_common(self, 0, key, flags);
}

static void *
array_map_lookup_elem_percpu(struct ebpf_map *self, void *key, uint64_t flags)
{
	return array_map_lookup_elem_common(self, ebpf_curcpu(), key, flags);
}

static int
array_map_delete_elem_common(struct ebpf_map *self, uint16_t idx, void *key)
{
	struct ebpf_map_array **maps = (struct ebpf_map_array **)self->data;
	struct ebpf_map_array *map = maps[idx];

	if (map->counter == 0) {
		return ENOENT;
	}

	uint32_t *k = (uint32_t *)key;
	if (*k >= self->max_entries) {
		return EINVAL;
	}

	if (!map->array[*k]) {
		return ENOENT;
	}

	ebpf_free(map->array[*k]);
	map->array[*k] = NULL;
	map->counter--;

	return 0;
}

static int
array_map_delete_elem(struct ebpf_map *self, void *key)
{
	return array_map_delete_elem_common(self, 0, key);
}

static int
array_map_delete_elem_percpu(struct ebpf_map *self, void *key)
{
	return array_map_delete_elem_common(self, ebpf_curcpu(), key);
}

static int
array_map_get_next_key(struct ebpf_map *self, void *key, void *next_key)
{
	struct ebpf_map_array **maps = (struct ebpf_map_array **)self->data;
	struct ebpf_map_array *map = (struct ebpf_map_array *)maps[0];
	uint32_t *nk = (uint32_t *)next_key;
	uint32_t cur, end;

	if (key == NULL || *(uint32_t *)key == self->max_entries - 1) {
		cur = 0;
		end = self->max_entries - 1;
	} else if (*(uint32_t *)key >= self->max_entries) {
		return EINVAL;
	} else {
		cur = (*(uint32_t *)key) + 1;
		end = *(uint32_t *)key;
	}

	do {
		if (map->array[cur]) {
			*nk = cur;
			return 0;
		}

		if (cur == self->max_entries - 1) {
			cur = 0;
		} else {
			cur++;
		}
	} while (cur != end);

	return ENOENT;
}

static void
array_map_deinit_common(struct ebpf_map *self, uint16_t num_maps)
{
	struct ebpf_map_array **maps = (struct ebpf_map_array **)self->data;
	struct ebpf_map_array *map;

	for (int i = 0; i < num_maps; i++) {
		map = maps[i];
		for (int j = 0; j < self->max_entries; j++) {
			if (map->array[j]) {
				ebpf_free(map->array[j]);
			}
		}
		ebpf_free(map);
	}
}

static void
array_map_deinit(struct ebpf_map *self, void *arg)
{
	array_map_deinit_common(self, 1);
}

static void
array_map_deinit_percpu(struct ebpf_map *self, void *arg)
{
	array_map_deinit_common(self, ebpf_ncpus());
}

const struct ebpf_map_ops array_map_ops = {.init = array_map_init,
					   .update_elem = array_map_update_elem,
					   .lookup_elem = array_map_lookup_elem,
					   .delete_elem = array_map_delete_elem,
					   .get_next_key =
					       array_map_get_next_key,
					   .deinit = array_map_deinit};

const struct ebpf_map_ops percpu_array_map_ops = {
    .init = array_map_init_percpu,
    .update_elem = array_map_update_elem_percpu,
    .lookup_elem = array_map_lookup_elem_percpu,
    .delete_elem = array_map_delete_elem_percpu,
    .get_next_key = NULL,
    .deinit = array_map_deinit_percpu};
