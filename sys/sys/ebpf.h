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

#define EBPF_NAME_MAX 64

enum ebpf_basic_map_types {
	EBPF_MAP_TYPE_BAD = 0,
	EBPF_MAP_TYPE_ARRAY,
	EBPF_MAP_TYPE_PERCPU_ARRAY,
	EBPF_MAP_TYPE_HASHTABLE,
	EBPF_MAP_TYPE_PERCPU_HASHTABLE,
	EBPF_MAP_TYPE_MAX
};

enum ebpf_basic_prog_types {
	EBPF_PROG_TYPE_BAD,
	EBPF_PROG_TYPE_TEST,
	EBPF_PROG_TYPE_MAX
};

enum ebpf_map_update_flags {
	EBPF_ANY = 0,
	EBPF_NOEXIST,
	EBPF_EXIST,
	__EBPF_MAP_UPDATE_FLAGS_MAX
};

#define EBPF_PROG_MAX_ATTACHED_MAPS 64
