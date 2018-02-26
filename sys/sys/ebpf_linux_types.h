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

enum ebpf_map_types {
  EBPF_MAP_TYPE_ARRAY = 0,
  EBPF_MAP_TYPE_PERCPU_ARRAY,
  EBPF_MAP_TYPE_TOMMYHASHTBL,
  __EBPF_MAP_TYPE_MAX
};

enum ebpf_prog_types {
  EBPF_PROG_TYPE_TEST = 0,
  EBPF_PROG_TYPE_VALE_BPF,
  __EBPF_PROG_TYPE_MAX
};
