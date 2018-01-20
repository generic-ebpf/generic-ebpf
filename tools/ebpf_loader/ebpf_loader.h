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
#include <stdbool.h>
#include <sys/ioctl.h>
#include <gelf.h>

#include <sys/ebpf_inst.h>
#include <sys/ebpf_uapi.h>

#include "ebpf_driver.h"

#ifdef DEBUG
#define D(_fmt, ...) fprintf(stderr, _fmt "\n", ##__VA_ARGS__)
#else
#define D(_fmt, ...) ;
#endif

// Section definitions
#define PROG_SEC    ".text"
#define MAP_SEC     "maps"
#define RELOC_SEC ".rel"PROG_SEC

struct ebpf_map_entry {
  int map_desc;
  char *name;
  struct ebpf_map_def *def;
};

typedef struct ebpf_loader_ctx {
  EBPFDriver *driver;
  Elf *elf;
  Elf_Data *prog;
  Elf_Data *maps;
  Elf_Data *symbols;
  Elf_Data *relocations;
  int prog_desc;
  struct ebpf_map_entry *map_entries[EBPF_PROG_MAX_ATTACHED_MAPS];
  uint16_t num_map_entries;
} EBPFLoader;

#define EBPF_PROG(_loader) _loader->prog ? _loader->prog->d_buf : NULL
#define EBPF_PROG_LEN(_loader) _loader->prog ? \
  _loader->prog->d_size / sizeof(struct ebpf_inst) : 0
#define EBPF_MAP_ENTRIES(_loader) _loader->map_entries
#define EBPF_NUM_MAP_ENTRIES(_loader) _loader->num_map_entries

EBPFLoader* ebpf_loader_create(EBPFDriver *driver);
int ebpf_loader_execute(EBPFLoader *loader, char *fname, uint16_t prog_type);
void ebpf_loader_destroy(EBPFLoader *loader);

// define getters for Python
struct ebpf_inst *ebpf_loader_get_prog(EBPFLoader *loader);
uint16_t ebpf_loader_get_map_num(EBPFLoader *loader);
struct ebpf_map_entry *ebpf_loader_get_map_entry(EBPFLoader *loader, uint16_t idx);
