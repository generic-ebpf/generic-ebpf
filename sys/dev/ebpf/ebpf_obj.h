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

#include <dev/ebpf/ebpf_platform.h>

#define EBPF_OBJ_MAX_DEPS 128

struct ebpf_obj;

typedef void (*ebpf_obj_dtor)(struct ebpf_obj*);

enum ebpf_obj_type {
	EBPF_OBJ_TYPE_PROG,
	EBPF_OBJ_TYPE_MAP,
	EBPF_OBJ_TYPE_MAX
};

struct ebpf_obj {
	uint32_t ref;
	uint16_t type;
	uint16_t ndeps;
	void (*dtor)(struct ebpf_obj*);
};

void ebpf_obj_acquire(struct ebpf_obj *eo);
void ebpf_obj_release(struct ebpf_obj *eo);
