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
struct hash_elem {
	tommy_hashtable_node node;
	uint32_t key_size;
	uint8_t key[0];
};

#define hash_elem_get_value(elem) elem->key + elem->key_size

static int
hashtable_map_init_common(struct ebpf_map_hashtable *hash_map,
			  uint32_t key_size, uint32_t value_size,
			  uint32_t max_entries, uint32_t flags)
{
	int error;

	error = tommy_hashtable_init(&hash_map->hashtable, max_entries);
	if (error) {
		return error;
	}

	uint64_t elem_size = sizeof(struct hash_elem) + key_size + value_size;

	ebpf_rw_init(&hash_map->rw, "ebpf_hashtable_map_lock");
	ebpf_allocator_init(&hash_map->allocator, elem_size, 8);

	error = ebpf_allocator_prealloc(&hash_map->allocator, max_entries);
	if (error) {
		goto err0;
	}

	return 0;

err0:
	ebpf_allocator_deinit(&hash_map->allocator);
	tommy_hashtable_done(&hash_map->hashtable);
	return error;
}

static int
hashtable_map_init(struct ebpf_map *map, uint32_t key_size, uint32_t value_size,
		   uint32_t max_entries, uint32_t flags)
{
	int error;

	struct ebpf_map_hashtable *hash_map =
	    ebpf_calloc(1, sizeof(struct ebpf_map_hashtable));
	if (!hash_map) {
		return ENOMEM;
	}

	error = hashtable_map_init_common(hash_map, key_size, value_size,
					  max_entries, flags);
	if (error) {
		ebpf_free(hash_map);
		return error;
	}

	map->data = hash_map;
	map->percpu = false;

	return 0;
}

static void
hashtable_map_deinit_common(struct ebpf_map_hashtable *hash_map, void *arg)
{
	ebpf_rw_destroy(&hash_map->rw);
	ebpf_allocator_deinit(&hash_map->allocator);
	tommy_hashtable_done(&hash_map->hashtable);
	ebpf_free(hash_map);
}

static void
hashtable_map_deinit(struct ebpf_map *map, void *arg)
{
	hashtable_map_deinit_common(map->data, arg);
}

static int
hashtable_map_cmp(const void *a, const void *b)
{
	const struct hash_elem *elem = (const struct hash_elem *)b;
	return memcmp(a, elem->key, elem->key_size);
}

static void *
__hashtable_map_lookup_elem_common(struct ebpf_map *map,
				   struct ebpf_map_hashtable *hashtable,
				   void *key, uint32_t hashval, uint64_t flags)
{
	if (tommy_hashtable_count(&hashtable->hashtable) == 0) {
		return NULL;
	}

	struct hash_elem *elem = tommy_hashtable_search(
	    &hashtable->hashtable, hashtable_map_cmp, key, hashval);
	if (!elem) {
		return NULL;
	}

	return hash_elem_get_value(elem);
}

static void *
hashtable_map_lookup_elem_common(struct ebpf_map *map,
				 struct ebpf_map_hashtable *hashtable,
				 void *key, uint64_t flags)
{
	return __hashtable_map_lookup_elem_common(
	    map, hashtable, key, tommy_hash_u32(0, key, map->key_size), flags);
}

static void *
hashtable_map_lookup_elem(struct ebpf_map *map, void *key, uint64_t flags)
{
	void *ret;
	struct ebpf_map_hashtable *hash_map = map->data;

	ebpf_rw_rlock(&hash_map->rw);
	ret = hashtable_map_lookup_elem_common(map, hash_map, key, flags);
	ebpf_rw_runlock(&hash_map->rw);

	return ret;
}

static int
hashtable_map_update_elem_common(struct ebpf_map *map,
				 struct ebpf_map_hashtable *hash_map, void *key,
				 void *value, uint64_t flags)
{
	if (tommy_hashtable_count(&hash_map->hashtable) == map->max_entries) {
		return EBUSY;
	}

	uint32_t hashval = tommy_hash_u32(0, key, map->key_size);
	struct hash_elem *elem = __hashtable_map_lookup_elem_common(
	    map, hash_map, key, hashval, flags);
	if (elem) {
		if (flags & EBPF_NOEXIST) {
			return EEXIST;
		}
		memcpy(elem, value, map->value_size);
		return 0;
	}

	if (flags & EBPF_EXIST) {
		return ENOENT;
	}

	elem = ebpf_allocator_alloc(&hash_map->allocator);
	if (!elem) {
		return ENOMEM;
	}

	elem->key_size = map->key_size;
	memcpy(elem->key, key, map->key_size);
	memcpy(hash_elem_get_value(elem), value, map->value_size);

	tommy_hashtable_insert(&hash_map->hashtable, &elem->node, elem,
			       hashval);

	return 0;
}

static int
hashtable_map_update_elem(struct ebpf_map *map, void *key, void *value,
			  uint64_t flags)
{
	int ret;
	struct ebpf_map_hashtable *hash_map = map->data;

	ebpf_rw_wlock(&hash_map->rw);
	ret =
	    hashtable_map_update_elem_common(map, hash_map, key, value, flags);
	ebpf_rw_wunlock(&hash_map->rw);

	return ret;
}

static int
hashtable_map_delete_elem_common(struct ebpf_map *map,
				 struct ebpf_map_hashtable *hashtable,
				 void *key)
{
	if (tommy_hashtable_count(&hashtable->hashtable) == 0) {
		return ENOENT;
	}

	struct hash_elem *elem =
	    tommy_hashtable_remove(&hashtable->hashtable, hashtable_map_cmp,
				   key, tommy_hash_u32(0, key, map->key_size));
	if (elem == 0) {
		return ENOENT;
	}

	ebpf_allocator_free(&hashtable->allocator, elem);

	return 0;
}

static int
hashtable_map_delete_elem(struct ebpf_map *map, void *key)
{
	int ret;
	struct ebpf_map_hashtable *hash_map = map->data;

	ebpf_rw_wlock(&hash_map->rw);
	ret = hashtable_map_delete_elem_common(map, hash_map, key);
	ebpf_rw_wunlock(&hash_map->rw);

	return ret;
}

static int
hashtable_map_get_next_key_common(struct ebpf_map *map,
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
	    &hashtable->hashtable, tommy_hash_u32(0, key, map->key_size));
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
	struct hash_elem *elem = (struct hash_elem *)node->data;
	memcpy(next_key, elem->key, map->key_size);

	return 0;

get_first_key:
	for (int i = pos; i < table->bucket_max + pos; i++) {
		cur = i % table->bucket_max;
		if (table->bucket[cur]) {
			struct hash_elem *elem =
			    (struct hash_elem *)table->bucket[cur]->data;
			memcpy(next_key, elem->key, map->key_size);
			break;
		}
	}

	return 0;
}

static int
hashtable_map_get_next_key(struct ebpf_map *map, void *key, void *next_key)
{
	int ret;
	struct ebpf_map_hashtable *hash_map = map->data;

	ebpf_rw_rlock(&hash_map->rw);
	ret = hashtable_map_get_next_key_common(map, hash_map, key, next_key);
	ebpf_rw_runlock(&hash_map->rw);

	return ret;
}

struct ebpf_map_ops hashtable_map_ops = {
    .init = hashtable_map_init,
    .update_elem = hashtable_map_update_elem,
    .lookup_elem = hashtable_map_lookup_elem,
    .delete_elem = hashtable_map_delete_elem,
    .update_elem_from_user = hashtable_map_update_elem,
    .lookup_elem_from_user = hashtable_map_lookup_elem,
    .delete_elem_from_user = hashtable_map_delete_elem,
    .get_next_key_from_user = hashtable_map_get_next_key,
    .deinit = hashtable_map_deinit};
