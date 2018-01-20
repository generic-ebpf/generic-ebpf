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

#include <stdint.h>

struct ebpf_driver;
typedef struct ebpf_driver EBPFDriver;

typedef int (ebpf_load_prog_t)(EBPFDriver *self, uint16_t prog_type,
    void *prog, uint32_t prog_len);
typedef int (ebpf_map_create_t)(EBPFDriver *self, uint16_t type,
    uint32_t key_size, uint32_t value_size, uint32_t max_entries,
    uint32_t map_flags);
typedef int (ebpf_map_update_elem_t)(EBPFDriver *self, int map_desc,
    void *key, void *value, uint64_t flags);
typedef int (ebpf_map_lookup_elem_t)(EBPFDriver *self, int map_desc,
    void *key, void *value, uint64_t flags);
typedef int (ebpf_map_delete_elem_t)(EBPFDriver *self, int map_desc,
    void *key);
typedef int (ebpf_map_get_next_key_t)(EBPFDriver *self, int map_desc,
    void *key, void *next_key);
typedef void (ebpf_close_prog_desc_t)(EBPFDriver *self, int prog_desc);
typedef void (ebpf_close_map_desc_t)(EBPFDriver *self, int map_desc);

struct ebpf_driver {
  ebpf_load_prog_t *load_prog;
  ebpf_map_create_t *map_create;
  ebpf_map_update_elem_t *map_update_elem;
  ebpf_map_lookup_elem_t *map_lookup_elem;
  ebpf_map_delete_elem_t *map_delete_elem;
  ebpf_map_get_next_key_t *map_get_next_key;
  ebpf_close_prog_desc_t *close_prog_desc;
  ebpf_close_map_desc_t *close_map_desc;
};

int ebpf_load_prog(EBPFDriver *driver, uint16_t prog_type, void *prog, uint32_t prog_len);
int ebpf_map_create(EBPFDriver *driver, uint16_t type, uint32_t key_size,
    uint32_t value_size, uint32_t max_entries, uint32_t map_flags);
int ebpf_map_update_elem(EBPFDriver *driver, int map_desc, void *key, void *value, uint64_t flags);
int ebpf_map_lookup_elem(EBPFDriver *driver, int map_desc, void *key, void *value, uint64_t flags);
int ebpf_map_delete_elem(EBPFDriver *driver, int map_desc, void *key);
int ebpf_map_get_next_key(EBPFDriver *driver, int map_desc, void *key, void  *next_key);
void ebpf_close_prog_desc(EBPFDriver *driver, int prog_desc);
void ebpf_close_map_desc(EBPFDriver *driver, int map_desc);
