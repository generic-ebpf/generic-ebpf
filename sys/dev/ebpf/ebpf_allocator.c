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

#include "ebpf_allocator.h"

void
ebpf_allocator_init(ebpf_allocator_t *alloc, uint32_t block_size,
		    uint32_t align_size)
{
	tommy_allocator_init(&alloc->allocator, block_size, align_size);
}

void
ebpf_allocator_deinit(ebpf_allocator_t *alloc)
{
	tommy_allocator_done(&alloc->allocator);
}

void*
ebpf_allocator_alloc(ebpf_allocator_t *alloc)
{
	return tommy_allocator_alloc(&alloc->allocator);
}

void
ebpf_allocator_free(ebpf_allocator_t *alloc, void *ptr)
{
	tommy_allocator_free(&alloc->allocator, ptr);
}

int
ebpf_allocator_prealloc(ebpf_allocator_t *alloc, uint32_t num)
{
	void *tmp;
	for (uint32_t i = 0; i < num; i++) {
		tmp = ebpf_allocator_alloc(alloc);
		if (!tmp) {
			return ENOMEM;
		}
		ebpf_allocator_free(alloc, tmp);
	}
	return 0;
}
