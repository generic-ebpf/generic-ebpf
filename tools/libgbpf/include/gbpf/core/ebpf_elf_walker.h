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

#include "ebpf_driver.h"

struct ebpf_elf_walker;
typedef struct ebpf_elf_walker EBPFElfWalker;

struct ebpf_elf_walker {
  void (*on_prog)(EBPFElfWalker *walker, const char *name,
      struct ebpf_inst *prog, uint32_t prog_len);
  void (*on_map)(EBPFElfWalker *walker, const char *name,
      int desc, struct ebpf_map_def *map);
  void *data;
};

int ebpf_walk_elf(EBPFElfWalker *walker, EBPFDriver *driver, char *fname);
