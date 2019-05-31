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

#include <dev/ebpf/ebpf_obj.h>
#include <sys/ebpf.h>
#include <sys/ebpf_inst.h>

#define EOP_MAX_DEPS 64

struct ebpf_prog {
	struct ebpf_obj eo;
	uint16_t type;
	uint16_t ndep_maps;
	uint32_t prog_len;
	struct ebpf_inst *prog;
	struct ebpf_map *dep_maps[EOP_MAX_DEPS];
};

struct ebpf_prog_attr {
	uint16_t type;
	struct ebpf_inst *prog;
	uint32_t prog_len;
};

struct ebpf_prog_type {
	char name[EBPF_NAME_MAX];
};

const struct ebpf_prog_type *ebpf_get_prog_type(uint16_t type);
int ebpf_prog_create(struct ebpf_prog **eopp, struct ebpf_prog_attr *attr);
void ebpf_prog_destroy(struct ebpf_prog *);
int ebpf_prog_attach_map(struct ebpf_prog *, struct ebpf_map *em);
