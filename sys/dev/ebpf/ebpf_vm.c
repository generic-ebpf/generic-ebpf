/*-
 * SPDX-License-Identifier: Apache License 2.0
 *
 * Copyright 2015 Big Switch Networks, Inc
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
#include "ebpf_internal.h"

struct ebpf_vm *
ebpf_create(void)
{
	struct ebpf_vm *vm = ebpf_calloc(1, sizeof(*vm));
	if (vm == NULL) {
		return NULL;
	}

	vm->ext_funcs = ebpf_calloc(MAX_EXT_FUNCS, sizeof(*vm->ext_funcs));
	if (vm->ext_funcs == NULL) {
		ebpf_destroy(vm);
		return NULL;
	}

	vm->ext_func_names =
	    ebpf_calloc(MAX_EXT_FUNCS, sizeof(*vm->ext_func_names));
	if (vm->ext_func_names == NULL) {
		ebpf_destroy(vm);
		return NULL;
	}

	return vm;
}

void
ebpf_destroy(struct ebpf_vm *vm)
{
	if (!vm) {
		return;
	}

	if (vm->jitted) {
		ebpf_exfree(vm->jitted, vm->jitted_size);
	}

	ebpf_free(vm->insts);
	ebpf_free(vm->ext_funcs);
	ebpf_free(vm->ext_func_names);
	ebpf_free(vm);
}

int
ebpf_register(struct ebpf_vm *vm, unsigned int idx, const char *name, void *fn)
{
	if (!vm || idx >= MAX_EXT_FUNCS || !name || !fn) {
		return -1;
	}

	vm->ext_funcs[idx] = (ext_func)fn;
	vm->ext_func_names[idx] = name;
	return 0;
}

unsigned int
ebpf_lookup_registered_function(struct ebpf_vm *vm, const char *name)
{
	if (!vm || !name) {
		return -1;
	}

	for (int i = 0; i < MAX_EXT_FUNCS; i++) {
		const char *other = vm->ext_func_names[i];
		if (other && !strcmp(other, name)) {
			return i;
		}
	}

	return -1;
}

int
ebpf_load(struct ebpf_vm *vm, const void *prog, uint32_t prog_len)
{
	if (!vm || !prog || prog_len == 0) {
		return -1;
	}

	if (vm->insts) {
		ebpf_unload(vm);
	}

	if (prog_len % sizeof(struct ebpf_inst) != 0) {
		ebpf_error("prog_len must be a multiple of 8\n");
		return -1;
	}

	if (!ebpf_validate(vm, prog, prog_len / sizeof(struct ebpf_inst))) {
		return -1;
	}

	vm->insts = ebpf_malloc(prog_len);
	if (vm->insts == NULL) {
		ebpf_error("out of memory\n");
		return -1;
	}

	memcpy(vm->insts, prog, prog_len);
	vm->num_insts = prog_len / sizeof(struct ebpf_inst);

	return 0;
}

void
ebpf_unload(struct ebpf_vm *vm)
{
	if (!vm) {
		return;
	}

	if (vm->jitted) {
		ebpf_exfree(vm->jitted, vm->jitted_size);
	}

	if (vm->insts) {
		ebpf_free(vm->insts);
		vm->insts = NULL;
	}
}

static uint32_t
uint32(uint64_t x)
{
	return x;
}

uint64_t
ebpf_exec(const struct ebpf_vm *vm, void *mem, size_t mem_len)
{
	uint16_t pc = 0;
	const struct ebpf_inst *insts;
	uint64_t reg[16];
	uint64_t stack[(STACK_SIZE + 7) / 8];

	if (!vm) {
		return UINT64_MAX;
	}

	if (!vm->insts) {
		/* Code must be loaded before we can execute */
		return UINT64_MAX;
	}

	insts = vm->insts;
	reg[1] = (uintptr_t)mem;
	reg[10] = (uintptr_t)stack + sizeof(stack);

	while (1) {
		const uint16_t cur_pc = pc;
		struct ebpf_inst inst = insts[pc++];

		switch (inst.opcode) {
		case EBPF_OP_ADD_IMM:
			reg[inst.dst] += inst.imm;
			reg[inst.dst] &= UINT32_MAX;
			break;
		case EBPF_OP_ADD_REG:
			reg[inst.dst] += reg[inst.src];
			reg[inst.dst] &= UINT32_MAX;
			break;
		case EBPF_OP_SUB_IMM:
			reg[inst.dst] -= inst.imm;
			reg[inst.dst] &= UINT32_MAX;
			break;
		case EBPF_OP_SUB_REG:
			reg[inst.dst] -= reg[inst.src];
			reg[inst.dst] &= UINT32_MAX;
			break;
		case EBPF_OP_MUL_IMM:
			reg[inst.dst] *= inst.imm;
			reg[inst.dst] &= UINT32_MAX;
			break;
		case EBPF_OP_MUL_REG:
			reg[inst.dst] *= reg[inst.src];
			reg[inst.dst] &= UINT32_MAX;
			break;
		case EBPF_OP_DIV_IMM:
			reg[inst.dst] =
			    uint32(reg[inst.dst]) / uint32(inst.imm);
			reg[inst.dst] &= UINT32_MAX;
			break;
		case EBPF_OP_DIV_REG:
			if (reg[inst.src] == 0) {
				ebpf_error("division by zero at PC %u\n",
					   cur_pc);
				return UINT64_MAX;
			}
			reg[inst.dst] =
			    uint32(reg[inst.dst]) / uint32(reg[inst.src]);
			reg[inst.dst] &= UINT32_MAX;
			break;
		case EBPF_OP_OR_IMM:
			reg[inst.dst] |= inst.imm;
			reg[inst.dst] &= UINT32_MAX;
			break;
		case EBPF_OP_OR_REG:
			reg[inst.dst] |= reg[inst.src];
			reg[inst.dst] &= UINT32_MAX;
			break;
		case EBPF_OP_AND_IMM:
			reg[inst.dst] &= inst.imm;
			reg[inst.dst] &= UINT32_MAX;
			break;
		case EBPF_OP_AND_REG:
			reg[inst.dst] &= reg[inst.src];
			reg[inst.dst] &= UINT32_MAX;
			break;
		case EBPF_OP_LSH_IMM:
			reg[inst.dst] <<= inst.imm;
			reg[inst.dst] &= UINT32_MAX;
			break;
		case EBPF_OP_LSH_REG:
			reg[inst.dst] <<= reg[inst.src];
			reg[inst.dst] &= UINT32_MAX;
			break;
		case EBPF_OP_RSH_IMM:
			reg[inst.dst] = uint32(reg[inst.dst]) >> inst.imm;
			reg[inst.dst] &= UINT32_MAX;
			break;
		case EBPF_OP_RSH_REG:
			reg[inst.dst] = uint32(reg[inst.dst]) >> reg[inst.src];
			reg[inst.dst] &= UINT32_MAX;
			break;
		case EBPF_OP_NEG:
			reg[inst.dst] = -reg[inst.dst];
			reg[inst.dst] &= UINT32_MAX;
			break;
		case EBPF_OP_MOD_IMM:
			reg[inst.dst] =
			    uint32(reg[inst.dst]) % uint32(inst.imm);
			reg[inst.dst] &= UINT32_MAX;
			break;
		case EBPF_OP_MOD_REG:
			if (reg[inst.src] == 0) {
				ebpf_error("division by zero at PC %u\n",
					   cur_pc);
				return UINT64_MAX;
			}
			reg[inst.dst] =
			    uint32(reg[inst.dst]) % uint32(reg[inst.src]);
			break;
		case EBPF_OP_XOR_IMM:
			reg[inst.dst] ^= inst.imm;
			reg[inst.dst] &= UINT32_MAX;
			break;
		case EBPF_OP_XOR_REG:
			reg[inst.dst] ^= reg[inst.src];
			reg[inst.dst] &= UINT32_MAX;
			break;
		case EBPF_OP_MOV_IMM:
			reg[inst.dst] = inst.imm;
			reg[inst.dst] &= UINT32_MAX;
			break;
		case EBPF_OP_MOV_REG:
			reg[inst.dst] = reg[inst.src];
			reg[inst.dst] &= UINT32_MAX;
			break;
		case EBPF_OP_ARSH_IMM:
			reg[inst.dst] = (int32_t)reg[inst.dst] >> inst.imm;
			reg[inst.dst] &= UINT32_MAX;
			break;
		case EBPF_OP_ARSH_REG:
			reg[inst.dst] =
			    (int32_t)reg[inst.dst] >> uint32(reg[inst.src]);
			reg[inst.dst] &= UINT32_MAX;
			break;

		case EBPF_OP_LE:
			if (inst.imm == 16) {
				reg[inst.dst] = htole16(reg[inst.dst]);
			} else if (inst.imm == 32) {
				reg[inst.dst] = htole32(reg[inst.dst]);
			} else if (inst.imm == 64) {
				reg[inst.dst] = htole64(reg[inst.dst]);
			}
			break;
		case EBPF_OP_BE:
			if (inst.imm == 16) {
				reg[inst.dst] = htobe16(reg[inst.dst]);
			} else if (inst.imm == 32) {
				reg[inst.dst] = htobe32(reg[inst.dst]);
			} else if (inst.imm == 64) {
				reg[inst.dst] = htobe64(reg[inst.dst]);
			}
			break;

		case EBPF_OP_ADD64_IMM:
			reg[inst.dst] += inst.imm;
			break;
		case EBPF_OP_ADD64_REG:
			reg[inst.dst] += reg[inst.src];
			break;
		case EBPF_OP_SUB64_IMM:
			reg[inst.dst] -= inst.imm;
			break;
		case EBPF_OP_SUB64_REG:
			reg[inst.dst] -= reg[inst.src];
			break;
		case EBPF_OP_MUL64_IMM:
			reg[inst.dst] *= inst.imm;
			break;
		case EBPF_OP_MUL64_REG:
			reg[inst.dst] *= reg[inst.src];
			break;
		case EBPF_OP_DIV64_IMM:
			reg[inst.dst] /= inst.imm;
			break;
		case EBPF_OP_DIV64_REG:
			if (reg[inst.src] == 0) {
				ebpf_error("division by zero at PC %u\n",
					   cur_pc);
				return UINT64_MAX;
			}
			reg[inst.dst] /= reg[inst.src];
			break;
		case EBPF_OP_OR64_IMM:
			reg[inst.dst] |= inst.imm;
			break;
		case EBPF_OP_OR64_REG:
			reg[inst.dst] |= reg[inst.src];
			break;
		case EBPF_OP_AND64_IMM:
			reg[inst.dst] &= inst.imm;
			break;
		case EBPF_OP_AND64_REG:
			reg[inst.dst] &= reg[inst.src];
			break;
		case EBPF_OP_LSH64_IMM:
			reg[inst.dst] <<= inst.imm;
			break;
		case EBPF_OP_LSH64_REG:
			reg[inst.dst] <<= reg[inst.src];
			break;
		case EBPF_OP_RSH64_IMM:
			reg[inst.dst] >>= inst.imm;
			break;
		case EBPF_OP_RSH64_REG:
			reg[inst.dst] >>= reg[inst.src];
			break;
		case EBPF_OP_NEG64:
			reg[inst.dst] = -reg[inst.dst];
			break;
		case EBPF_OP_MOD64_IMM:
			reg[inst.dst] %= inst.imm;
			break;
		case EBPF_OP_MOD64_REG:
			if (reg[inst.src] == 0) {
				ebpf_error("division by zero at PC %u\n",
					   cur_pc);
				return UINT64_MAX;
			}
			reg[inst.dst] %= reg[inst.src];
			break;
		case EBPF_OP_XOR64_IMM:
			reg[inst.dst] ^= inst.imm;
			break;
		case EBPF_OP_XOR64_REG:
			reg[inst.dst] ^= reg[inst.src];
			break;
		case EBPF_OP_MOV64_IMM:
			reg[inst.dst] = inst.imm;
			break;
		case EBPF_OP_MOV64_REG:
			reg[inst.dst] = reg[inst.src];
			break;
		case EBPF_OP_ARSH64_IMM:
			reg[inst.dst] = (int64_t)reg[inst.dst] >> inst.imm;
			break;
		case EBPF_OP_ARSH64_REG:
			reg[inst.dst] = (int64_t)reg[inst.dst] >> reg[inst.src];
			break;

		case EBPF_OP_LDXW:
			reg[inst.dst] = *(uint32_t *)(uintptr_t)(reg[inst.src] +
								 inst.offset);
			break;
		case EBPF_OP_LDXH:
			reg[inst.dst] = *(uint16_t *)(uintptr_t)(reg[inst.src] +
								 inst.offset);
			break;
		case EBPF_OP_LDXB:
			reg[inst.dst] = *(uint8_t *)(uintptr_t)(reg[inst.src] +
								inst.offset);
			break;
		case EBPF_OP_LDXDW:
			reg[inst.dst] = *(uint64_t *)(uintptr_t)(reg[inst.src] +
								 inst.offset);
			break;

		case EBPF_OP_STW:
			*(uint32_t *)(uintptr_t)(reg[inst.dst] + inst.offset) =
			    inst.imm;
			break;
		case EBPF_OP_STH:
			*(uint16_t *)(uintptr_t)(reg[inst.dst] + inst.offset) =
			    inst.imm;
			break;
		case EBPF_OP_STB:
			*(uint8_t *)(uintptr_t)(reg[inst.dst] + inst.offset) =
			    inst.imm;
			break;
		case EBPF_OP_STDW:
			*(uint64_t *)(uintptr_t)(reg[inst.dst] + inst.offset) =
			    inst.imm;
			break;

		case EBPF_OP_STXW:
			*(uint32_t *)(uintptr_t)(reg[inst.dst] + inst.offset) =
			    reg[inst.src];
			break;
		case EBPF_OP_STXH:
			*(uint16_t *)(uintptr_t)(reg[inst.dst] + inst.offset) =
			    reg[inst.src];
			break;
		case EBPF_OP_STXB:
			*(uint8_t *)(uintptr_t)(reg[inst.dst] + inst.offset) =
			    reg[inst.src];
			break;
		case EBPF_OP_STXDW:
			*(uint64_t *)(uintptr_t)(reg[inst.dst] + inst.offset) =
			    reg[inst.src];
			break;

		case EBPF_OP_LDDW:
			reg[inst.dst] = (uint32_t)inst.imm |
					((uint64_t)insts[pc++].imm << 32);
			break;

		case EBPF_OP_JA:
			pc += inst.offset;
			break;
		case EBPF_OP_JEQ_IMM:
			if (reg[inst.dst] == inst.imm) {
				pc += inst.offset;
			}
			break;
		case EBPF_OP_JEQ_REG:
			if (reg[inst.dst] == reg[inst.src]) {
				pc += inst.offset;
			}
			break;
		case EBPF_OP_JGT_IMM:
			if (reg[inst.dst] > (uint32_t)inst.imm) {
				pc += inst.offset;
			}
			break;
		case EBPF_OP_JGT_REG:
			if (reg[inst.dst] > reg[inst.src]) {
				pc += inst.offset;
			}
			break;
		case EBPF_OP_JGE_IMM:
			if (reg[inst.dst] >= (uint32_t)inst.imm) {
				pc += inst.offset;
			}
			break;
		case EBPF_OP_JGE_REG:
			if (reg[inst.dst] >= reg[inst.src]) {
				pc += inst.offset;
			}
			break;
		case EBPF_OP_JLT_IMM:
			if (reg[inst.dst] < (uint32_t)inst.imm) {
				pc += inst.offset;
			}
			break;
		case EBPF_OP_JLT_REG:
			if (reg[inst.dst] < reg[inst.src]) {
				pc += inst.offset;
			}
			break;
		case EBPF_OP_JLE_IMM:
			if (reg[inst.dst] <= (uint32_t)inst.imm) {
				pc += inst.offset;
			}
			break;
		case EBPF_OP_JLE_REG:
			if (reg[inst.dst] <= reg[inst.src]) {
				pc += inst.offset;
			}
			break;
		case EBPF_OP_JSET_IMM:
			if (reg[inst.dst] & inst.imm) {
				pc += inst.offset;
			}
			break;
		case EBPF_OP_JSET_REG:
			if (reg[inst.dst] & reg[inst.src]) {
				pc += inst.offset;
			}
			break;
		case EBPF_OP_JNE_IMM:
			if (reg[inst.dst] != inst.imm) {
				pc += inst.offset;
			}
			break;
		case EBPF_OP_JNE_REG:
			if (reg[inst.dst] != reg[inst.src]) {
				pc += inst.offset;
			}
			break;
		case EBPF_OP_JSGT_IMM:
			if ((int64_t)reg[inst.dst] > inst.imm) {
				pc += inst.offset;
			}
			break;
		case EBPF_OP_JSGT_REG:
			if ((int64_t)reg[inst.dst] > (int64_t)reg[inst.src]) {
				pc += inst.offset;
			}
			break;
		case EBPF_OP_JSGE_IMM:
			if ((int64_t)reg[inst.dst] >= inst.imm) {
				pc += inst.offset;
			}
			break;
		case EBPF_OP_JSGE_REG:
			if ((int64_t)reg[inst.dst] >= (int64_t)reg[inst.src]) {
				pc += inst.offset;
			}
			break;
		case EBPF_OP_JSLT_IMM:
			if ((int64_t)reg[inst.dst] < inst.imm) {
				pc += inst.offset;
			}
			break;
		case EBPF_OP_JSLT_REG:
			if ((int64_t)reg[inst.dst] < (int64_t)reg[inst.src]) {
				pc += inst.offset;
			}
			break;
		case EBPF_OP_JSLE_IMM:
			if ((int64_t)reg[inst.dst] <= inst.imm) {
				pc += inst.offset;
			}
			break;
		case EBPF_OP_JSLE_REG:
			if ((int64_t)reg[inst.dst] <= (int64_t)reg[inst.src]) {
				pc += inst.offset;
			}
			break;
		case EBPF_OP_EXIT:
			return reg[0];
		case EBPF_OP_CALL:
			reg[0] = vm->ext_funcs[inst.imm](reg[1], reg[2], reg[3],
							 reg[4], reg[5]);
			break;
		default:
			ebpf_error("Unknown instruction!\n");
			return UINT64_MAX;
		}
	}
}

uint64_t
ebpf_exec_jit(const struct ebpf_vm *vm, void *mem, size_t mem_len)
{
	if (!vm) {
		return UINT64_MAX;
	}

	if (vm->jitted) {
		return vm->jitted(mem, mem_len);
	} else {
		return UINT64_MAX;
	}
}
