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

#include "ebpf_prog_test.h"
#include "ebpf_prog.h"
#include "ebpf_map.h"
#include <sys/ebpf_vm.h>

static void
test_vm_attach_func(struct ebpf_vm *vm)
{
	/*
	 * Attach basic external functions
	 */
	ebpf_register(vm, 1, "ebpf_map_update_elem", ebpf_map_update_elem);
	ebpf_register(vm, 2, "ebpf_map_lookup_elem", ebpf_map_lookup_elem);
	ebpf_register(vm, 3, "ebpf_map_delete_elem", ebpf_map_delete_elem);
}

int
ebpf_run_test(struct ebpf_inst *prog, uint32_t prog_len,
		void *ctx, uint32_t ctx_len, bool jit, uint64_t *result)
{
	int error = 0;

	/*
	 * ctx == NULL is valid, because it is possible to write
	 * eBPF program which doesn't require context structure.
	 */
	if (prog == NULL || prog_len == 0 ||
			result == NULL || (ctx != NULL && ctx_len == 0)) {
		return EINVAL;
	}

	struct ebpf_vm *vm = ebpf_create();
	if (vm == NULL) {
		return ENOMEM;
	}

	test_vm_attach_func(vm);

	error = ebpf_load(vm, prog, prog_len);
	if (error < 0) {
		error = EINVAL;
		goto err0;
	}

	if (jit) {
		ebpf_jit_fn fn = ebpf_compile(vm);
		if (!fn) {
			error = EINVAL;
			goto err0;
		}
		*result = ebpf_exec_jit(vm, ctx, ctx_len);
	} else {
		*result = ebpf_exec(vm, ctx, ctx_len);
	}

err0:
	ebpf_destroy(vm);
	return error;
}

struct ebpf_prog_type test_prog_type = {
	.name = "test"
};
