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

#pragma once

#include "ebpf_platform.h"
#include "tommyds/tommyalloc.h"

typedef struct ebpf_allocator_s {
	tommy_allocator allocator;
} ebpf_allocator_t;

void ebpf_allocator_init(ebpf_allocator_t *alloc, uint32_t block_size,
			 uint32_t align_size);
void ebpf_allocator_deinit(ebpf_allocator_t *alloc);
void *ebpf_allocator_alloc(ebpf_allocator_t *alloc);
void ebpf_allocator_free(ebpf_allocator_t *alloc, void *ptr);
int ebpf_allocator_prealloc(ebpf_allocator_t *alloc, uint32_t num);
