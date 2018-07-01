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
#include "ebpf_util.h"

/*
 * This should be trimmed
 */
#define HASH_MAP_NEXTRA_ELEMS 1

struct ebpf_map_hashtable;

/*
 * hashtable_map's element. Actual value is following to
 * variable length key.
 */
struct hash_elem {
	EBPF_EPOCH_LIST_ENTRY(hash_elem) elem;
	ebpf_epoch_context_t ec;
	struct ebpf_map_hashtable *hash_map;
	uint32_t key_size;
	uint8_t key[0];
};

struct hash_bucket {
	EBPF_EPOCH_LIST_HEAD(, hash_elem) head;
	ebpf_mtx_t lock;
};

struct ebpf_map_hashtable {
	uint32_t count;
	uint32_t elem_size;
	uint32_t nbuckets;
	struct hash_bucket *buckets;
	ebpf_allocator_t allocator;
	ebpf_epoch_context_t ec;
};

#define hash_elem_get_value(elem) elem->key + elem->key_size

static struct hash_bucket *
hashtable_map_get_bucket(struct ebpf_map_hashtable *hash_map, uint32_t hash)
{
	return &hash_map->buckets[hash & (hash_map->nbuckets - 1)];
}

static struct hash_elem *
hash_bucket_lookup_elem(struct hash_bucket *bucket, void *key, uint32_t key_size)
{
	struct hash_elem *elem;

	EBPF_EPOCH_LIST_FOREACH(elem, &bucket->head, elem) {
		if (memcmp(elem->key, key, key_size) == 0) {
			return elem;
		}
	}

	return NULL;
}

static int
hashtable_map_init(struct ebpf_map *map, uint32_t key_size, uint32_t value_size,
		   uint32_t max_entries, uint32_t flags)
{
	int error;

	/*
	 * Roundup key_size and value_size for efficiency.
	 * However, users or eBPF programs still can't access
	 * to extra bytes.
	 */
	key_size = ebpf_roundup(key_size, 8);
	value_size = ebpf_roundup(value_size, 8);

	/* Check overflow */
	if (key_size + value_size + sizeof(struct hash_elem) > UINT32_MAX) {
		return E2BIG;
	}

	struct ebpf_map_hashtable *hash_map =
	    ebpf_calloc(1, sizeof(struct ebpf_map_hashtable));
	if (!hash_map) {
		return ENOMEM;
	}

	ebpf_refcount_init(&hash_map->count, 0);
	hash_map->elem_size = key_size + value_size + sizeof(struct hash_elem);

	/*
	 * Roundup number of buckets to power of two.
	 * This improbes performance, because we don't have to
	 * use slow moduro opearation.
	 */
	hash_map->nbuckets = ebpf_roundup_pow_of_two(max_entries);
	hash_map->buckets =
		ebpf_calloc(hash_map->nbuckets, sizeof(struct hash_bucket));
	if (!hash_map->buckets) {
		error = ENOMEM;
		goto err0;
	}

	for (uint32_t i = 0; i < hash_map->nbuckets; i++) {
		EBPF_EPOCH_LIST_INIT(&hash_map->buckets[i].head);
		ebpf_mtx_init(&hash_map->buckets[i].lock, "ebpf_hashtable_map bucket lock");
	}

	error = ebpf_allocator_init(&hash_map->allocator, hash_map->elem_size);
	if (error) {
		goto err1;
	}

	/* 
	 * All hashtable elements are preallocated in default.
	 * In the future version, it should be specified by flags.
	 *
	 * Few numbers of extra elements are allocated to avoid
	 * extra malloc() called when we are waiting for physical
	 * release of map element.
	 */
	error = ebpf_allocator_prealloc(&hash_map->allocator,
			max_entries + ebpf_ncpus() + HASH_MAP_NEXTRA_ELEMS);
	if (error) {
		goto err2;
	}

	map->data = hash_map;
	map->percpu = false;

	return 0;

err2:
	ebpf_allocator_deinit(&hash_map->allocator);
err1:
	ebpf_free(hash_map->buckets);
err0:
	ebpf_free(hash_map);
	return error;
}

/*
 * This function should be called under condition which no one
 * except the pending callbacks registered by ebpf_epoch_call
 * can access to the map. Then, we can correctly release map.
 *
 * For example, in ebpf_dev case, program which uses maps holds
 * reference count to maps. Then, hashtable_map_deinit called
 * when map file's reference count becomes zero. This means no
 * eBPF programs are under executing (because they are called under
 * epoch critical section) and no userspace programs are referring
 * the map.
 */
static void
hashtable_map_deinit(struct ebpf_map *map, void *arg)
{
	struct ebpf_map_hashtable *hash_map = map->data;

	/*
	 * Wait for release of all map elements
	 */
	ebpf_epoch_wait();
	ebpf_allocator_deinit(&hash_map->allocator);
	ebpf_free(hash_map->buckets);
	ebpf_free(hash_map);
}

static void *
hashtable_map_lookup_elem(struct ebpf_map *map, void *key)
{
	struct ebpf_map_hashtable *hash_map = map->data;
	if (hash_map->count == 0) {
		return NULL;
	}

	struct hash_bucket *bucket = 
		hashtable_map_get_bucket(hash_map, ebpf_jenkins_hash(key, map->key_size, 0));

	struct hash_elem *elem = hash_bucket_lookup_elem(bucket, key, map->key_size);
	if (!elem) {
		return NULL;
	}

	return hash_elem_get_value(elem);
}

static int
check_update_flags(struct ebpf_map_hashtable *hash_map,
		struct hash_elem *elem, uint64_t flags)
{
	if (elem) {
		if (flags & EBPF_NOEXIST) {
			return EEXIST;
		}
	} else {
		if (flags & EBPF_EXIST) {
			return ENOENT;
		}
	}

	return 0;
}

static int
hashtable_map_update_elem(struct ebpf_map *map, void *key,
		void *value, uint64_t flags)
{
	int error = 0;
	struct hash_bucket *bucket;
	struct hash_elem *old_elem, *new_elem;
	struct ebpf_map_hashtable *hash_map = map->data;

	if (hash_map->count == map->max_entries) {
		return EBUSY;
	}

	bucket = hashtable_map_get_bucket(hash_map,
			ebpf_jenkins_hash(key, map->key_size, 0));

	ebpf_mtx_lock(&bucket->lock);

	old_elem = hash_bucket_lookup_elem(bucket, key, map->key_size);
	error = check_update_flags(hash_map, old_elem, flags);
	if (error) {
		goto err0;
	}

	new_elem = ebpf_allocator_alloc(&hash_map->allocator);
	if (!new_elem) {
		error = ENOMEM;
		goto err0;
	}

	new_elem->key_size = map->key_size;
	memcpy(new_elem->key, key, map->key_size);
	memcpy(hash_elem_get_value(new_elem), value, map->value_size);

	/*
	 * Insert element to list head. Then readers after this operation
	 * may see new element.
	 */
	bool need_wait;
	EBPF_EPOCH_LIST_INSERT_HEAD(&bucket->head, new_elem, elem);
	if (old_elem) {
		EBPF_EPOCH_LIST_REMOVE(old_elem, elem);
		old_elem->hash_map = hash_map;
		need_wait = true;
	} else {
		ebpf_refcount_acquire(&hash_map->count);
		need_wait = false;
	}

	ebpf_mtx_unlock(&bucket->lock);

	if (need_wait) {
		ebpf_epoch_wait();
		ebpf_allocator_free(&hash_map->allocator, old_elem);
	}

	return error;

err0:
	ebpf_mtx_unlock(&bucket->lock);
	return error;
}

static int
hashtable_map_delete_elem(struct ebpf_map *map, void *key)
{
	struct ebpf_map_hashtable *hash_map = map->data;
	struct hash_bucket *bucket;
	struct hash_elem *elem;

	bucket = hashtable_map_get_bucket(hash_map,
			ebpf_jenkins_hash(key, map->key_size, 0));

	ebpf_mtx_lock(&bucket->lock);

	elem = hash_bucket_lookup_elem(bucket, key, map->key_size);
	if (elem) {
		ebpf_refcount_release(&hash_map->count);
		EBPF_EPOCH_LIST_REMOVE(elem, elem);
		elem->hash_map = hash_map;
		ebpf_epoch_wait();
		ebpf_allocator_free(&hash_map->allocator, elem);
	}

	ebpf_mtx_unlock(&bucket->lock);

	return 0;
}

static int
hashtable_map_get_next_key(struct ebpf_map *map, void *key, void *next_key)
{
	struct ebpf_map_hashtable *hash_map = map->data;
	struct hash_bucket *bucket;
	struct hash_elem *elem, *next_elem;
	uint32_t hash = 0;
	int i = 0;

	if (hash_map->count == 0 ||
			(hash_map->count == 1 && key != NULL)) {
		return ENOENT;
	}

	if (key == NULL) {
		goto get_first_key;
	}

	hash = ebpf_jenkins_hash(key, map->key_size, 0);
	bucket = hashtable_map_get_bucket(hash_map, hash);
	elem = hash_bucket_lookup_elem(bucket, key, map->key_size);
	if (!elem) {
		goto get_first_key;
	}

	next_elem = EBPF_EPOCH_LIST_NEXT(elem, elem);
	if (next_elem) {
		memcpy(next_key, next_elem->key, map->key_size);
		return 0;
	}

	i = (hash & (hash_map->nbuckets - 1)) + 1;

get_first_key:
	for (; i < hash_map->nbuckets; i++) {
		bucket = hash_map->buckets + i;
		EBPF_EPOCH_LIST_FOREACH(elem, &bucket->head, elem) {
			memcpy(next_key, elem->key, map->key_size);
			return 0;
		}
	}

	return ENOENT;
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
