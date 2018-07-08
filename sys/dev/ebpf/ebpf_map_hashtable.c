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

struct ebpf_map_hashtable;

/*
 * hashtable_map's element. Actual value is following to
 * variable length key.
 */
struct hash_elem {
	EBPF_EPOCH_LIST_ENTRY(hash_elem) elem;
	ebpf_epoch_context_t ec;
	struct ebpf_map_hashtable *hash_map;
	uint8_t key[0];
};

struct hash_bucket {
	EBPF_EPOCH_LIST_HEAD(, hash_elem) head;
	ebpf_mtx_t lock;
};

struct ebpf_map_hashtable {
	uint32_t elem_size;
	uint32_t key_size;   /* round upped key size */
	uint32_t value_size; /* round uppped value size */
	uint32_t nbuckets;
	struct hash_bucket *buckets;
	struct hash_elem **pcpu_extra_elems;
	ebpf_allocator_t allocator;
	ebpf_epoch_context_t ec;
};

#define HASH_ELEM_VALUE(_hash_mapp, _elemp) _elemp->key + _hash_mapp->key_size
#define HASH_BUCKET_LOCK(_bucketp) ebpf_mtx_lock(&_bucketp->lock);
#define HASH_BUCKET_UNLOCK(_bucketp) ebpf_mtx_unlock(&_bucketp->lock);

static struct hash_bucket *
get_hash_bucket(struct ebpf_map_hashtable *hash_map, uint32_t hash)
{
	return &hash_map->buckets[hash & (hash_map->nbuckets - 1)];
}

static struct hash_elem *
get_hash_elem(struct hash_bucket *bucket, void *key, uint32_t key_size)
{
	struct hash_elem *elem;
	EBPF_EPOCH_LIST_FOREACH(elem, &bucket->head, elem)
	{
		if (memcmp(elem->key, key, key_size) == 0) {
			return elem;
		}
	}
	return NULL;
}

static struct hash_elem *
get_extra_elem(struct ebpf_map_hashtable *hash_map, struct hash_elem *elem)
{
	struct hash_elem *tmp;
	tmp = hash_map->pcpu_extra_elems[ebpf_curcpu()];
	hash_map->pcpu_extra_elems[ebpf_curcpu()] = elem;
	return tmp;
}

static int
check_update_flags(struct ebpf_map_hashtable *hash_map, struct hash_elem *elem,
		   uint64_t flags)
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
hashtable_map_init(struct ebpf_map *map, uint32_t key_size, uint32_t value_size,
		   uint32_t max_entries, uint32_t flags)
{
	int error;

	/* Check overflow */
	if (ebpf_roundup(key_size, 8) + ebpf_roundup(value_size, 8) +
		sizeof(struct hash_elem) >
	    UINT32_MAX) {
		return E2BIG;
	}

	struct ebpf_map_hashtable *hash_map =
	    ebpf_calloc(1, sizeof(struct ebpf_map_hashtable));
	if (!hash_map) {
		return ENOMEM;
	}

	/*
	 * Roundup key size and value size for efficiency.
	 * This affects sizeof element. Never allow users
	 * to see "padded" memory region.
	 *
	 * Here we cache the "internal" key_size and value_size.
	 * For getting the "real" key_size and value_size, please
	 * use values stored in struct ebpf_map.
	 */
	hash_map->key_size = ebpf_roundup(key_size, 8);
	hash_map->value_size = ebpf_roundup(value_size, 8);
	hash_map->elem_size = hash_map->key_size + hash_map->value_size +
			      sizeof(struct hash_elem);

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
		ebpf_mtx_init(&hash_map->buckets[i].lock,
			      "ebpf_hashtable_map bucket lock");
	}

	error = ebpf_allocator_init(&hash_map->allocator, hash_map->elem_size,
				    max_entries + ebpf_ncpus());
	if (error) {
		goto err1;
	}

	hash_map->pcpu_extra_elems =
	    ebpf_calloc(ebpf_ncpus(), sizeof(struct hash_elem *));
	if (!hash_map->pcpu_extra_elems) {
		error = ENOMEM;
		goto err2;
	}

	/*
	 * Reserve percpu extra map element in here.
	 * These elemens are useful to update existing
	 * map element. Since updating is running at
	 * critical section, we don't require any lock
	 * to take this element.
	 */
	for (uint32_t i = 0; i < ebpf_ncpus(); i++) {
		hash_map->pcpu_extra_elems[i] =
		    ebpf_allocator_alloc(&hash_map->allocator);
		ebpf_assert(hash_map->pcpu_extra_elems);
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

static void
hashtable_map_deinit(struct ebpf_map *map, void *arg)
{
	struct ebpf_map_hashtable *hash_map = map->data;

	/*
	 * Wait for current readers
	 */
	ebpf_epoch_wait();

	ebpf_allocator_deinit(&hash_map->allocator);

	for (uint32_t i = 0; i < hash_map->nbuckets; i++) {
		ebpf_mtx_destroy(&hash_map->buckets[i].lock);
	}

	ebpf_free(hash_map->buckets);
	ebpf_free(hash_map->pcpu_extra_elems);
	ebpf_free(hash_map);
}

static void *
hashtable_map_lookup_elem(struct ebpf_map *map, void *key)
{
	uint32_t hash = ebpf_jenkins_hash(key, map->key_size, 0);
	struct ebpf_map_hashtable *hash_map;
	struct hash_bucket *bucket;
	struct hash_elem *elem;

	hash_map = map->data;
	bucket = get_hash_bucket(hash_map, hash);
	elem = get_hash_elem(bucket, key, map->key_size);
	if (!elem) {
		return NULL;
	}

	return HASH_ELEM_VALUE(hash_map, elem);
}

static int
hashtable_map_update_elem(struct ebpf_map *map, void *key, void *value,
			  uint64_t flags)
{
	int error = 0;
	uint32_t hash = ebpf_jenkins_hash(key, map->key_size, 0);
	struct hash_bucket *bucket;
	struct hash_elem *old_elem, *new_elem;
	struct ebpf_map_hashtable *hash_map = map->data;

	bucket = get_hash_bucket(hash_map, hash);
	old_elem = get_hash_elem(bucket, key, map->key_size);
	error = check_update_flags(hash_map, old_elem, flags);
	if (error) {
		return error;
	}

	if (old_elem) {
		/*
		 * In case of updating existing element, we can
		 * use percpu extra elements and swap it with old
		 * element. This avoids take lock of memory allocator.
		 */
		new_elem = get_extra_elem(hash_map, old_elem);
	} else {
		new_elem = ebpf_allocator_alloc(&hash_map->allocator);
		if (!new_elem) {
			return EBUSY;
		}
	}

	memcpy(new_elem->key, key, map->key_size);
	memcpy(HASH_ELEM_VALUE(hash_map, new_elem), value, map->value_size);

	HASH_BUCKET_LOCK(bucket);

	EBPF_EPOCH_LIST_INSERT_HEAD(&bucket->head, new_elem, elem);
	if (old_elem) {
		EBPF_EPOCH_LIST_REMOVE(old_elem, elem);
	}

	HASH_BUCKET_UNLOCK(bucket);

	return error;
}

static int
hashtable_map_delete_elem(struct ebpf_map *map, void *key)
{
	uint32_t hash = ebpf_jenkins_hash(key, map->key_size, 0);
	struct ebpf_map_hashtable *hash_map = map->data;
	struct hash_bucket *bucket;
	struct hash_elem *elem;

	bucket = get_hash_bucket(hash_map, hash);

	HASH_BUCKET_LOCK(bucket);

	elem = get_hash_elem(bucket, key, map->key_size);
	if (elem) {
		EBPF_EPOCH_LIST_REMOVE(elem, elem);
	}

	HASH_BUCKET_UNLOCK(bucket);

	/*
	 * Just return element to memory allocator without any
	 * synchronization. This is safe, because ebpf_allocator
	 * never calls free().
	 */
	if (elem) {
		ebpf_allocator_free(&hash_map->allocator, elem);
	}

	return 0;
}

static int
hashtable_map_get_next_key(struct ebpf_map *map, void *key, void *next_key)
{
	struct ebpf_map_hashtable *hash_map = map->data;
	struct hash_bucket *bucket;
	struct hash_elem *elem, *next_elem;
	uint32_t hash = 0;
	uint32_t i = 0;

	if (key == NULL) {
		goto get_first_key;
	}

	hash = ebpf_jenkins_hash(key, map->key_size, 0);
	bucket = get_hash_bucket(hash_map, hash);
	elem = get_hash_elem(bucket, key, map->key_size);
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
		EBPF_EPOCH_LIST_FOREACH(elem, &bucket->head, elem)
		{
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
