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

#include "ebpf_platform.h"
#include <sys/ebpf.h>

/*
 * ebpf object type description
 */
enum ebpf_obj_type {
    EBPF_OBJ_TYPE_PROG = 0,
    EBPF_OBJ_TYPE_MAP,
    __EBPF_OBJ_TYPE_MAX
};

/*
 * All ebpf object struct must contain below structure
 * on top of it
 */
struct ebpf_obj {
    uint16_t obj_type;
};

/*
 * ebpf program
 */
struct ebpf_obj_prog {
    uint16_t obj_type;
    uint16_t prog_type;
    uint32_t prog_len;
    struct ebpf_inst *prog;
};

/*
 * ebpf map
 */
struct ebpf_obj_map {
    uint16_t obj_type;
    uint16_t map_type;
    uint32_t key_size;
    uint32_t value_size;
    uint32_t map_flags;
    uint32_t max_entries;
    uint32_t num_entries;
    void *data;
};

int ebpf_obj_new(struct ebpf_obj **obj, uint16_t type, union ebpf_req *req);
void ebpf_obj_delete(struct ebpf_obj *obj);
