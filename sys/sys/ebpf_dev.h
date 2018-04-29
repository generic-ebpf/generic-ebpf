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

#include <sys/ebpf.h>

union ebpf_req {
    // Attribute of EBPFIOC_LOAD_PROG
    struct {
        int *prog_fdp;
        uint16_t prog_type;
        uint32_t prog_len;
        void *prog;
    };
    // Attribute of EBPFIOC_MAP_CREATE
    struct {
        int *map_fdp;
        uint32_t map_type;
        uint32_t key_size;
        uint32_t value_size;
        uint32_t max_entries;
        uint32_t map_flags;
    };
    // Attribute of EBPFIOC_MAP_*_ELEM and EBPFIOC_MAP_GET_*_KEY
    struct {
        int map_fd;
        void *key;
        union {
            void *value;
            void *next_key;
        };
        uint64_t flags;
    };
    // Attribute of EBPFIOC_RUN_TEST
    struct {
        int prog_fd;
        void *ctx;
        uint16_t ctx_len;
        int jit;
        uint64_t *test_result;
    };
};

#define EBPFIOC_LOAD_PROG _IOWR('i', 151, union ebpf_req)
#define EBPFIOC_MAP_CREATE _IOWR('i', 152, union ebpf_req)
#define EBPFIOC_MAP_LOOKUP_ELEM _IOWR('i', 153, union ebpf_req)
#define EBPFIOC_MAP_UPDATE_ELEM _IOWR('i', 154, union ebpf_req)
#define EBPFIOC_MAP_DELETE_ELEM _IOWR('i', 155, union ebpf_req)
#define EBPFIOC_MAP_GET_NEXT_KEY _IOWR('i', 156, union ebpf_req)
#define EBPFIOC_RUN_TEST _IOWR('i', 157, union ebpf_req)
