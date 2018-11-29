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

#include "ebpf_platform.h"
#include <sys/ebpf.h>

struct ebpf_obj_type {
	uint32_t eot_refcount;
	char eot_name[EBPF_NAME_MAX];
	char eot_description[EBPF_DESC_MAX];
};

struct ebpf_obj_type_registry {
	ebpf_mtx mtx;
	struct ebpf_obj_type *types[EBPF_TYPE_MAX];
};

int ebpf_obj_type_init(struct ebpf_obj_type *type);
int ebpf_obj_type_registry_init(struct ebpf_obj_type_registry *registry);
int ebpf_obj_type_register(struct ebpf_obj_type_registry *registry, struct ebpf_obj_type *type, uint16_t *idxp);
int ebpf_obj_type_unregister(struct ebpf_obj_type_registry *registry, uint16_t idx);
int ebpf_obj_type_acquire(struct ebpf_obj_type_registry *registry, uint16_t idx, struct ebpf_obj_type **typep);
int ebpf_obj_type_release(struct ebpf_obj_type *type);
int ebpf_obj_type_lookup(struct ebpf_obj_type_registry *registry, const char *name, uint16_t *idxp);
