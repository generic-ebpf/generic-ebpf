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
#include "tommyds/tommyhashtbl.h"

struct ebpf_map_hashtable {
	ebpf_rwlock_t rw;
	ebpf_allocator_t allocator;
	tommy_hashtable hashtable;
};

// element = node + key + value
struct ebpf_map_hashtable_elem {
	tommy_hashtable_node node;
	uint32_t key_size;
	uint8_t key[0];
};

#define hashtable_map_elem_get_value(elem) elem->key + elem->key_size

static int
hashtable_map_init_common(struct ebpf_map_hashtable *self, uint32_t key_size,
			  uint32_t value_size, uint32_t max_entries,
			  uint32_t flags)
{
	int error;

	tommy_hashtable_init(&self->hashtable, max_entries);

	uint64_t elem_size =
	    sizeof(struct ebpf_map_hashtable_elem) + key_size + value_size;

	ebpf_rw_init(&self->rw, "ebpf_hashtable_map_lock");
	ebpf_allocator_init(&self->allocator, elem_size, 8);

	error = ebpf_allocator_prealloc(&self->allocator, max_entries);
	if (error) {
		goto err0;
	}

	return 0;

err0:
	ebpf_allocator_deinit(&self->allocator);
	tommy_hashtable_done(&self->hashtable);
	return error;
}

static int
hashtable_map_init(struct ebpf_map *self, uint32_t key_size,
		   uint32_t value_size, uint32_t max_entries, uint32_t flags)
{
	int error;

	struct ebpf_map_hashtable *map =
	    ebpf_malloc(sizeof(struct ebpf_map_hashtable));
	if (!map) {
		return ENOMEM;
	}

	error = hashtable_map_init_common(map, key_size, value_size,
					  max_entries, flags);
	if (error) {
		ebpf_free(map);
		return error;
	}

	self->data = map;

	return 0;
}

static void
hashtable_map_deinit_common(struct ebpf_map_hashtable *self, void *arg)
{
	ebpf_rw_destroy(&self->rw);
	ebpf_allocator_deinit(&self->allocator);
	tommy_hashtable_done(&self->hashtable);
	ebpf_free(self);
}

static void
hashtable_map_deinit(struct ebpf_map *self, void *arg)
{
	hashtable_map_deinit_common(self->data, arg);
}

static int
hashtable_map_cmp(const void *a, const void *b)
{
	const struct ebpf_map_hashtable_elem *elem =
	    (const struct ebpf_map_hashtable_elem *)b;
	return memcmp(a, elem->key, elem->key_size);
}

static void *
hashtable_map_lookup_elem_common(struct ebpf_map *self,
				 struct ebpf_map_hashtable *hashtable,
				 uint32_t *key, uint64_t flags)
{
	if (tommy_hashtable_count(&hashtable->hashtable) == 0) {
		return NULL;
	}

	struct ebpf_map_hashtable_elem *elem =
	    tommy_hashtable_search(&hashtable->hashtable, hashtable_map_cmp,
				   key, tommy_hash_u64(0, key, self->key_size));
	if (!elem) {
		return NULL;
	}

	return hashtable_map_elem_get_value(elem);
}

static void *
hashtable_map_lookup_elem(struct ebpf_map *self, void *key, uint64_t flags)
{
	void *ret;
	struct ebpf_map_hashtable *map = self->data;

	ebpf_rw_rlock(&map->rw);
	ret = hashtable_map_lookup_elem_common(self, map, key, flags);
	ebpf_rw_runlock(&map->rw);

	return ret;
}

static int
hashtable_map_update_elem_common(struct ebpf_map *self,
				 struct ebpf_map_hashtable *hashtable,
				 void *key, void *value, uint64_t flags)
{
	if (tommy_hashtable_count(&hashtable->hashtable) == self->max_entries) {
		return EBUSY;
	}

	struct ebpf_map_hashtable_elem *elem =
	    hashtable_map_lookup_elem_common(self, hashtable, key, flags);
	if (elem) {
		if (flags & EBPF_NOEXIST) {
			return EEXIST;
		}
		memcpy(elem, value, self->value_size);
		return 0;
	}

	if (flags & EBPF_EXIST) {
		return ENOENT;
	}

	elem = ebpf_allocator_alloc(&hashtable->allocator);
	if (!elem) {
		return ENOMEM;
	}

	elem->key_size = self->key_size;
	memcpy(elem->key, key, self->key_size);
	memcpy(hashtable_map_elem_get_value(elem), value, self->value_size);

	tommy_hashtable_insert(&hashtable->hashtable, &elem->node, elem,
			       tommy_hash_u64(0, elem->key, self->key_size));

	return 0;
}

static int
hashtable_map_update_elem(struct ebpf_map *self, void *key, void *value,
			  uint64_t flags)
{
	int ret;
	struct ebpf_map_hashtable *map = self->data;

	ebpf_rw_wlock(&map->rw);
	ret = hashtable_map_update_elem_common(self, map, key, value, flags);
	ebpf_rw_wunlock(&map->rw);

	return ret;
}

static int
hashtable_map_delete_elem_common(struct ebpf_map *self,
				 struct ebpf_map_hashtable *hashtable,
				 void *key)
{
	if (tommy_hashtable_count(&hashtable->hashtable) == 0) {
		return ENOENT;
	}

	struct ebpf_map_hashtable_elem *elem =
	    tommy_hashtable_remove(&hashtable->hashtable, hashtable_map_cmp,
				   key, tommy_hash_u64(0, key, self->key_size));
	if (elem == 0) {
		return ENOENT;
	}

	ebpf_allocator_free(&hashtable->allocator, elem);

	return 0;
}

static int
hashtable_map_delete_elem(struct ebpf_map *self, void *key)
{
	int ret;
	struct ebpf_map_hashtable *map = self->data;

	ebpf_rw_wlock(&map->rw);
	ret = hashtable_map_delete_elem_common(self, map, key);
	ebpf_rw_wunlock(&map->rw);

	return ret;
}

static int
hashtable_map_get_next_key_common(struct ebpf_map *self,
				  struct ebpf_map_hashtable *hashtable,
				  void *key, void *next_key)
{
	int pos = 0, cur;
	tommy_hashtable *table = &hashtable->hashtable;

	if (tommy_hashtable_count(table) == 0 ||
	    (tommy_hashtable_count(table) == 1 && key != NULL)) {
		return ENOENT;
	}

	if (key == NULL) {
		goto get_first_key;
	}

	tommy_hashtable_node *node = tommy_hashtable_bucket(
	    &hashtable->hashtable, tommy_hash_u64(0, key, self->key_size));
	if (node->next == 0) {
		pos = node->key & table->bucket_mask;
		if (pos == table->bucket_max - 1) {
			pos = 0;
		} else {
			pos = pos + 1;
		}
		goto get_first_key;
	}

	node = node->next;
	struct ebpf_map_hashtable_elem *elem =
	    (struct ebpf_map_hashtable_elem *)node->data;
	memcpy(next_key, elem->key, self->key_size);

	return 0;

get_first_key:
	for (int i = pos; i < table->bucket_max + pos; i++) {
		cur = i % table->bucket_max;
		if (table->bucket[cur]) {
			struct ebpf_map_hashtable_elem *elem =
			    (struct ebpf_map_hashtable_elem *)table->bucket[cur]
				->data;
			memcpy(next_key, elem->key, self->key_size);
			break;
		}
	}

	return 0;
}

static int
hashtable_map_get_next_key(struct ebpf_map *self, void *key, void *next_key)
{
	int ret;
	struct ebpf_map_hashtable *map = self->data;

	ebpf_rw_rlock(&map->rw);
	ret = hashtable_map_get_next_key_common(self, map, key, next_key);
	ebpf_rw_runlock(&map->rw);

	return ret;
}

struct ebpf_map_ops hashtable_map_ops = {
    .init = hashtable_map_init,
    .update_elem = hashtable_map_update_elem,
    .lookup_elem = hashtable_map_lookup_elem,
    .delete_elem = hashtable_map_delete_elem,
    .get_next_key = hashtable_map_get_next_key,
    .update_elem_from_user = hashtable_map_update_elem,
    .lookup_elem_from_user = hashtable_map_lookup_elem,
    .delete_elem_from_user = hashtable_map_delete_elem,
    .get_next_key_from_user = hashtable_map_get_next_key,
    .deinit = hashtable_map_deinit};
