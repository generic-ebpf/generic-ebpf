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

#include "ebpf_prog.h"

static struct ebpf_obj_type_registry prog_type_registry;

int
ebpf_register_prog_type(struct ebpf_prog_type *type, uint16_t *idxp)
{
	return ebpf_obj_type_register(&prog_type_registry,
			(struct ebpf_obj_type *)type, idxp);
}

int
ebpf_unregister_prog_type(uint16_t idx)
{
	return ebpf_obj_type_unregister(&prog_type_registry, idx);
}

int
ebpf_acquire_prog_type(uint16_t idx, struct ebpf_prog_type **typep)
{
	return ebpf_obj_type_acquire(&prog_type_registry, idx,
			(struct ebpf_obj_type **)typep);
}

int
ebpf_release_prog_type(struct ebpf_prog_type *type)
{
	return ebpf_obj_type_release((struct ebpf_obj_type *)type);
}

static void
register_basic_prog(struct ebpf_prog_type *type, uint16_t *idxp, uint16_t expect)
{
	int error;
	ebpf_refcount_init(&type->ept_type.eot_refcount, 0);
	error = ebpf_register_prog_type(type, idxp);
	ebpf_assert(error == 0 && *idxp == expect);
}

static void
unregister_basic_prog(uint16_t idx)
{
	int error;
	error = ebpf_unregister_prog_type(idx);
	ebpf_assert(error == 0);
}

static bool
prog_type_is_used(struct ebpf_prog_type *type)
{
	return type->ept_type.eot_refcount != 0;
}

void
ebpf_init_prog_types(void)
{
	int error;
	uint16_t idx;

	error = ebpf_obj_type_registry_init(&prog_type_registry);
	ebpf_assert(error == 0);

	/*
	 * Register basic prog types
	 */
	register_basic_prog(&bad_prog_type, &idx, EBPF_PROG_TYPE_BAD);
	register_basic_prog(&test_prog_type, &idx, EBPF_PROG_TYPE_TEST);
}

int
ebpf_deinit_prog_types(void)
{
	static bool basic_prog_unregistered = false;

	if (basic_prog_unregistered == false) {
		unregister_basic_prog(EBPF_PROG_TYPE_BAD);
		unregister_basic_prog(EBPF_PROG_TYPE_TEST);
		basic_prog_unregistered = true;
	}

	if (prog_type_is_used(&bad_prog_type) ||
			prog_type_is_used(&test_prog_type)) {
		return EBUSY;
	}

	return 0;
}

int
ebpf_prog_init(struct ebpf_prog *prog_obj, uint16_t type,
	       struct ebpf_inst *prog, uint32_t prog_len)
{
	int error;

	if (!prog_obj || type >= __EBPF_PROG_TYPE_MAX || !prog || !prog_len) {
		return EINVAL;
	}

	struct ebpf_inst *insts = ebpf_malloc(prog_len);
	if (!insts) {
		return ENOMEM;
	}

	memcpy(insts, prog, prog_len);

	error = ebpf_acquire_prog_type(type, &prog_obj->type);
	if (error) {
		return error;
	}

	prog_obj->prog_len = prog_len;
	prog_obj->prog = insts;
	prog_obj->deinit = ebpf_prog_deinit_default;

	return 0;
}

void
ebpf_prog_deinit_default(struct ebpf_prog *prog_obj, void *arg)
{
	int error;
	ebpf_free(prog_obj->prog);
	error = ebpf_release_prog_type(prog_obj->type);
	ebpf_assert(error == 0);
}

void
ebpf_prog_deinit(struct ebpf_prog *prog_obj, void *arg)
{
	if (!prog_obj) {
		return;
	}

	if (prog_obj->deinit) {
		prog_obj->deinit(prog_obj, arg);
	}
}
