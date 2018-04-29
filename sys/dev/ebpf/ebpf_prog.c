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

#include "ebpf_platform.h"
#include "ebpf_prog.h"

int
ebpf_prog_init(struct ebpf_prog *prog_obj, uint16_t type,
	       struct ebpf_inst *prog, uint32_t prog_len)
{
	if (!prog_obj || type >= __EBPF_PROG_TYPE_MAX || !prog || !prog_len) {
		return EINVAL;
	}

	struct ebpf_inst *insts = ebpf_malloc(prog_len);
	if (!insts) {
		return ENOMEM;
	}
	memcpy(insts, prog, prog_len);

	prog_obj->type = type;
	prog_obj->prog_len = prog_len;
	prog_obj->prog = insts;
	prog_obj->deinit = ebpf_prog_deinit_default;

	return 0;
}

void
ebpf_prog_deinit_default(struct ebpf_prog *prog_obj, void *arg)
{
	ebpf_free(prog_obj->prog);
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
