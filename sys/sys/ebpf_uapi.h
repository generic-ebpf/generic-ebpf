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

enum ebpf_prog_types { EBPF_PROG_TYPE_TEST = 0, __EBPF_PROG_TYPE_MAX };

enum ebpf_map_types { EBPF_MAP_TYPE_ARRAY = 0, EBPF_MAP_TYPE_TOMMYHASHTBL, __EBPF_MAP_TYPE_MAX };

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

#define EBPF_PSEUDO_MAP_DESC 1
#define EBPF_PROG_MAX_ATTACHED_MAPS 64

struct ebpf_map_def {
  uint32_t type;
  uint32_t key_size;
  uint32_t value_size;
  uint32_t max_entries;
  uint32_t flags;
};
