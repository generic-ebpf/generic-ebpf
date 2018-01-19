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

#pragma once

#include <sys/ebpf.h>

struct ebpf_map_def {
  uint32_t type;
  uint32_t key_size;
  uint32_t value_size;
  uint32_t max_entries;
  uint32_t flags;
};

enum ebpf_common_functions {
  EBPF_FUNC_ebpf_map_update_elem = 0,
  EBPF_FUNC_ebpf_map_lookup_elem,
  EBPF_FUNC_ebpf_map_delete_elem,
  __EBPF_COMMON_FUNCTIONS_MAX
};

#define EBPF_FUNC(NAME, ...) \
  (*NAME)(__VA_ARGS__) __attribute__((__unused__)) = (void *) EBPF_FUNC_##NAME

// Definitions of common external functions
static int EBPF_FUNC(ebpf_map_update_elem, struct ebpf_map_def *map, void *key, void *value, uint64_t flags);
static void* EBPF_FUNC(ebpf_map_lookup_elem, struct ebpf_map_def *map, void *key, uint64_t flags);
static int EBPF_FUNC(ebpf_map_delete_elem, struct ebpf_map_def *map, void *key);
