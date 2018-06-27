/*-
 * SPDX-License-Identifier: Apache License 2.0
 *
 * Copyright 2018 Yutaro Hayakawa
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

#include "ebpf_allocator.h"

#define EBPF_ALLOCATOR_ALIGN sizeof(void *)

/*
 * Simple fixed size memory block allocator with free list
 * for eBPF maps.
 */

int
ebpf_allocator_init(ebpf_allocator_t *alloc, uint32_t block_size)
{
	if (block_size % EBPF_ALLOCATOR_ALIGN != 0 || block_size == 0) {
		return EINVAL;
	}

	alloc->block_size = block_size;
	SLIST_INIT(&alloc->free_block);
	SLIST_INIT(&alloc->used_segment);
	ebpf_mtx_init(&alloc->lock, "ebpf_allocator lock");

	return 0;
}

/*
 * Preallocate nblocks of memory block and keep it to
 * free list.
 */
int
ebpf_allocator_prealloc(ebpf_allocator_t *alloc, uint32_t nblocks)
{
	if (nblocks == 0) {
		return EINVAL;
	}

	void *tmp;
	for (uint32_t i = 0; i < nblocks; i++) {
		tmp = ebpf_allocator_alloc(alloc);
		if (!tmp) {
			return ENOMEM;
		}
		ebpf_allocator_free(alloc, tmp);
	}

	return 0;
}

void
ebpf_allocator_deinit(ebpf_allocator_t *alloc)
{
	ebpf_allocator_entry_t *tmp;
	while (!SLIST_EMPTY(&alloc->used_segment)) {
		tmp = SLIST_FIRST(&alloc->used_segment);
		SLIST_REMOVE_HEAD(&alloc->used_segment, entry);
		ebpf_free(tmp);
	}
}

/*
 * Allocates memory block from free list.
 *
 * When the free list is empty, first it calls malloc()
 * and allocate page size memory region, then split it
 * into multiple memory block. When memory block size
 * is larger than page size, it only allocates single
 * block. All blocks are aligned to EBPF_ALLOCATOR_ALIGN.
 */
void *
ebpf_allocator_alloc(ebpf_allocator_t *alloc)
{
	void *ret;

	ebpf_mtx_lock(&alloc->lock);

	if (SLIST_EMPTY(&alloc->free_block)) {
		uint32_t size;
		uint8_t *data;
		ebpf_allocator_entry_t *segment;

		size = ebpf_getpagesize();

		if (size < sizeof(ebpf_allocator_entry_t) +
				alloc->block_size + EBPF_ALLOCATOR_ALIGN) {
			size = sizeof(ebpf_allocator_entry_t) +
				alloc->block_size + EBPF_ALLOCATOR_ALIGN;
		}

		data = ebpf_malloc(size);
		if (!data) {
			return NULL;
		}

		segment = (ebpf_allocator_entry_t *)data;
		SLIST_INSERT_HEAD(&alloc->used_segment, segment, entry);
		data += sizeof(ebpf_allocator_entry_t);

		uintptr_t off, mis;

		off = (uintptr_t)data;
		mis = off % EBPF_ALLOCATOR_ALIGN;
		if (mis != 0) {
			data += EBPF_ALLOCATOR_ALIGN - mis;
			size -= EBPF_ALLOCATOR_ALIGN - mis;
		}

		do {
			SLIST_INSERT_HEAD(&alloc->free_block,
					(ebpf_allocator_entry_t *)data, entry);
			data += alloc->block_size;
			size -= alloc->block_size;
		} while (size > alloc->block_size);
	}

	ret = SLIST_FIRST(&alloc->free_block);
	SLIST_REMOVE_HEAD(&alloc->free_block, entry);

	ebpf_mtx_unlock(&alloc->lock);

	return ret;
}

/*
 * Put ptr into free list. It never calls free().
 */
void
ebpf_allocator_free(ebpf_allocator_t *alloc, void *ptr)
{
	if (alloc->count == 0) {
		return;
	}

	ebpf_mtx_lock(&alloc->lock);

	SLIST_INSERT_HEAD(&alloc->free_block,
			(ebpf_allocator_entry_t *)ptr, entry);

	ebpf_mtx_unlock(&alloc->lock);
}
