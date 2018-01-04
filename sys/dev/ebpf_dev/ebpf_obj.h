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

#include "ebpf_dev_platform.h"
#include <dev/ebpf/ebpf_map.h>
#include <dev/ebpf/ebpf_prog.h>
#include <sys/ebpf.h>
#include <sys/ebpf_dev.h>

enum ebpf_obj_type {
    EBPF_OBJ_TYPE_PROG = 0,
    EBPF_OBJ_TYPE_MAP,
    __EBPF_OBJ_TYPE_MAX
};

struct ebpf_obj {
    uint16_t type;
    ebpf_file_t *f;
};

struct ebpf_obj_map {
    struct ebpf_map map;
    struct ebpf_obj obj;
};

#define EBPF_OBJ_PROG_MAX_ATTACHED_MAPS EBPF_DEV_PROG_MAX_ATTACHED_MAPS
struct ebpf_obj_prog {
    struct ebpf_prog prog;
    struct ebpf_obj obj;
    struct ebpf_obj_map *attached_maps[EBPF_PROG_MAX_ATTACHED_MAPS];
    uint16_t nattached_maps;
};

void *ebpf_obj_container_of(struct ebpf_obj *obj);
void *ebpf_objfile_get_container(ebpf_file_t *fp);
void ebpf_obj_delete(struct ebpf_obj *obj, ebpf_thread_t *td);
