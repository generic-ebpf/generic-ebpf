/*-
 * SPDX-License-Identifier: Apache License 2.0
 *
 * Copyright 2015 Big Switch Networks, Inc
 * Copyright 2017 Google Inc.
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

#include <dev/ebpf/ebpf_platform.h>
#include <dev/ebpf/ebpf_internal.h>
#include <sys/ebpf.h>
#include "ebpf_jit_x86_64.h"

/* Special values for target_pc in struct jump */
#define TARGET_PC_EXIT -1
#define TARGET_PC_DIV_BY_ZERO -2

static void muldivmod(struct jit_state *state, uint16_t pc, uint8_t opcode,
		      int src, int dst, int32_t imm);

#define REGISTER_MAP_SIZE 11
static int register_map[REGISTER_MAP_SIZE] = {
    RAX, RDI, RSI, RDX, R9, R8, RBX, R13, R14, R15, RBP,
};

/* Return the x86 register for the given eBPF register */
static int
map_register(int r)
{
	ebpf_assert(r < REGISTER_MAP_SIZE);
	return register_map[r % REGISTER_MAP_SIZE];
}

static int
translate(struct ebpf_vm *vm, struct jit_state *state)
{
	emit_push(state, RBP);
	emit_push(state, RBX);
	emit_push(state, R13);
	emit_push(state, R14);
	emit_push(state, R15);

	/* Move rdi into register 1 */
	if (map_register(1) != RDI) {
		emit_mov(state, RDI, map_register(1));
	}

	/* Copy stack pointer to R10 */
	emit_mov(state, RSP, map_register(10));

	/* Allocate stack space */
	emit_alu64_imm32(state, 0x81, 5, RSP, STACK_SIZE);

	int i;
	for (i = 0; i < vm->num_insts; i++) {
		struct ebpf_inst inst = vm->insts[i];
		state->pc_locs[i] = state->offset;

		int dst = map_register(inst.dst);
		int src = map_register(inst.src);
		uint32_t target_pc = i + inst.offset + 1;

		switch (inst.opcode) {
		case EBPF_OP_ADD_IMM:
			emit_alu32_imm32(state, 0x81, 0, dst, inst.imm);
			break;
		case EBPF_OP_ADD_REG:
			emit_alu32(state, 0x01, src, dst);
			break;
		case EBPF_OP_SUB_IMM:
			emit_alu32_imm32(state, 0x81, 5, dst, inst.imm);
			break;
		case EBPF_OP_SUB_REG:
			emit_alu32(state, 0x29, src, dst);
			break;
		case EBPF_OP_MUL_IMM:
		case EBPF_OP_MUL_REG:
		case EBPF_OP_DIV_IMM:
		case EBPF_OP_DIV_REG:
		case EBPF_OP_MOD_IMM:
		case EBPF_OP_MOD_REG:
			muldivmod(state, i, inst.opcode, src, dst, inst.imm);
			break;
		case EBPF_OP_OR_IMM:
			emit_alu32_imm32(state, 0x81, 1, dst, inst.imm);
			break;
		case EBPF_OP_OR_REG:
			emit_alu32(state, 0x09, src, dst);
			break;
		case EBPF_OP_AND_IMM:
			emit_alu32_imm32(state, 0x81, 4, dst, inst.imm);
			break;
		case EBPF_OP_AND_REG:
			emit_alu32(state, 0x21, src, dst);
			break;
		case EBPF_OP_LSH_IMM:
			emit_alu32_imm8(state, 0xc1, 4, dst, inst.imm);
			break;
		case EBPF_OP_LSH_REG:
			emit_mov(state, src, RCX);
			emit_alu32(state, 0xd3, 4, dst);
			break;
		case EBPF_OP_RSH_IMM:
			emit_alu32_imm8(state, 0xc1, 5, dst, inst.imm);
			break;
		case EBPF_OP_RSH_REG:
			emit_mov(state, src, RCX);
			emit_alu32(state, 0xd3, 5, dst);
			break;
		case EBPF_OP_NEG:
			emit_alu32(state, 0xf7, 3, dst);
			break;
		case EBPF_OP_XOR_IMM:
			emit_alu32_imm32(state, 0x81, 6, dst, inst.imm);
			break;
		case EBPF_OP_XOR_REG:
			emit_alu32(state, 0x31, src, dst);
			break;
		case EBPF_OP_MOV_IMM:
			emit_alu32_imm32(state, 0xc7, 0, dst, inst.imm);
			break;
		case EBPF_OP_MOV_REG:
			emit_mov(state, src, dst);
			break;
		case EBPF_OP_ARSH_IMM:
			emit_alu32_imm8(state, 0xc1, 7, dst, inst.imm);
			break;
		case EBPF_OP_ARSH_REG:
			emit_mov(state, src, RCX);
			emit_alu32(state, 0xd3, 7, dst);
			break;

		case EBPF_OP_LE:
			/* No-op */
			break;
		case EBPF_OP_BE:
			if (inst.imm == 16) {
				/* rol */
				emit1(state, 0x66); /* 16-bit override */
				emit_alu32_imm8(state, 0xc1, 0, dst, 8);
				/* and */
				emit_alu32_imm32(state, 0x81, 4, dst, 0xffff);
			} else if (inst.imm == 32 || inst.imm == 64) {
				/* bswap */
				emit_basic_rex(state, inst.imm == 64, 0, dst);
				emit1(state, 0x0f);
				emit1(state, 0xc8 | (dst & 7));
			}
			break;

		case EBPF_OP_ADD64_IMM:
			emit_alu64_imm32(state, 0x81, 0, dst, inst.imm);
			break;
		case EBPF_OP_ADD64_REG:
			emit_alu64(state, 0x01, src, dst);
			break;
		case EBPF_OP_SUB64_IMM:
			emit_alu64_imm32(state, 0x81, 5, dst, inst.imm);
			break;
		case EBPF_OP_SUB64_REG:
			emit_alu64(state, 0x29, src, dst);
			break;
		case EBPF_OP_MUL64_IMM:
		case EBPF_OP_MUL64_REG:
		case EBPF_OP_DIV64_IMM:
		case EBPF_OP_DIV64_REG:
		case EBPF_OP_MOD64_IMM:
		case EBPF_OP_MOD64_REG:
			muldivmod(state, i, inst.opcode, src, dst, inst.imm);
			break;
		case EBPF_OP_OR64_IMM:
			emit_alu64_imm32(state, 0x81, 1, dst, inst.imm);
			break;
		case EBPF_OP_OR64_REG:
			emit_alu64(state, 0x09, src, dst);
			break;
		case EBPF_OP_AND64_IMM:
			emit_alu64_imm32(state, 0x81, 4, dst, inst.imm);
			break;
		case EBPF_OP_AND64_REG:
			emit_alu64(state, 0x21, src, dst);
			break;
		case EBPF_OP_LSH64_IMM:
			emit_alu64_imm8(state, 0xc1, 4, dst, inst.imm);
			break;
		case EBPF_OP_LSH64_REG:
			emit_mov(state, src, RCX);
			emit_alu64(state, 0xd3, 4, dst);
			break;
		case EBPF_OP_RSH64_IMM:
			emit_alu64_imm8(state, 0xc1, 5, dst, inst.imm);
			break;
		case EBPF_OP_RSH64_REG:
			emit_mov(state, src, RCX);
			emit_alu64(state, 0xd3, 5, dst);
			break;
		case EBPF_OP_NEG64:
			emit_alu64(state, 0xf7, 3, dst);
			break;
		case EBPF_OP_XOR64_IMM:
			emit_alu64_imm32(state, 0x81, 6, dst, inst.imm);
			break;
		case EBPF_OP_XOR64_REG:
			emit_alu64(state, 0x31, src, dst);
			break;
		case EBPF_OP_MOV64_IMM:
			emit_load_imm(state, dst, inst.imm);
			break;
		case EBPF_OP_MOV64_REG:
			emit_mov(state, src, dst);
			break;
		case EBPF_OP_ARSH64_IMM:
			emit_alu64_imm8(state, 0xc1, 7, dst, inst.imm);
			break;
		case EBPF_OP_ARSH64_REG:
			emit_mov(state, src, RCX);
			emit_alu64(state, 0xd3, 7, dst);
			break;

		/* TODO use 8 bit immediate when possible */
		case EBPF_OP_JA:
			emit_jmp(state, target_pc);
			break;
		case EBPF_OP_JEQ_IMM:
			emit_cmp_imm32(state, dst, inst.imm);
			emit_jcc(state, 0x84, target_pc);
			break;
		case EBPF_OP_JEQ_REG:
			emit_cmp(state, src, dst);
			emit_jcc(state, 0x84, target_pc);
			break;
		case EBPF_OP_JGT_IMM:
			emit_cmp_imm32(state, dst, inst.imm);
			emit_jcc(state, 0x87, target_pc);
			break;
		case EBPF_OP_JGT_REG:
			emit_cmp(state, src, dst);
			emit_jcc(state, 0x87, target_pc);
			break;
		case EBPF_OP_JGE_IMM:
			emit_cmp_imm32(state, dst, inst.imm);
			emit_jcc(state, 0x83, target_pc);
			break;
		case EBPF_OP_JGE_REG:
			emit_cmp(state, src, dst);
			emit_jcc(state, 0x83, target_pc);
			break;
		case EBPF_OP_JLT_IMM:
			emit_cmp_imm32(state, dst, inst.imm);
			emit_jcc(state, 0x82, target_pc);
			break;
		case EBPF_OP_JLT_REG:
			emit_cmp(state, src, dst);
			emit_jcc(state, 0x82, target_pc);
			break;
		case EBPF_OP_JLE_IMM:
			emit_cmp_imm32(state, dst, inst.imm);
			emit_jcc(state, 0x86, target_pc);
			break;
		case EBPF_OP_JLE_REG:
			emit_cmp(state, src, dst);
			emit_jcc(state, 0x86, target_pc);
			break;
		case EBPF_OP_JSET_IMM:
			emit_alu64_imm32(state, 0xf7, 0, dst, inst.imm);
			emit_jcc(state, 0x85, target_pc);
			break;
		case EBPF_OP_JSET_REG:
			emit_alu64(state, 0x85, src, dst);
			emit_jcc(state, 0x85, target_pc);
			break;
		case EBPF_OP_JNE_IMM:
			emit_cmp_imm32(state, dst, inst.imm);
			emit_jcc(state, 0x85, target_pc);
			break;
		case EBPF_OP_JNE_REG:
			emit_cmp(state, src, dst);
			emit_jcc(state, 0x85, target_pc);
			break;
		case EBPF_OP_JSGT_IMM:
			emit_cmp_imm32(state, dst, inst.imm);
			emit_jcc(state, 0x8f, target_pc);
			break;
		case EBPF_OP_JSGT_REG:
			emit_cmp(state, src, dst);
			emit_jcc(state, 0x8f, target_pc);
			break;
		case EBPF_OP_JSGE_IMM:
			emit_cmp_imm32(state, dst, inst.imm);
			emit_jcc(state, 0x8d, target_pc);
			break;
		case EBPF_OP_JSGE_REG:
			emit_cmp(state, src, dst);
			emit_jcc(state, 0x8d, target_pc);
			break;
		case EBPF_OP_JSLT_IMM:
			emit_cmp_imm32(state, dst, inst.imm);
			emit_jcc(state, 0x8c, target_pc);
			break;
		case EBPF_OP_JSLT_REG:
			emit_cmp(state, src, dst);
			emit_jcc(state, 0x8c, target_pc);
			break;
		case EBPF_OP_JSLE_IMM:
			emit_cmp_imm32(state, dst, inst.imm);
			emit_jcc(state, 0x8e, target_pc);
			break;
		case EBPF_OP_JSLE_REG:
			emit_cmp(state, src, dst);
			emit_jcc(state, 0x8e, target_pc);
			break;
		case EBPF_OP_CALL:
			/* We reserve RCX for shifts */
			emit_mov(state, R9, RCX);
			emit_call(state, vm->ext_funcs[inst.imm]);
			break;
		case EBPF_OP_EXIT:
			if (i != vm->num_insts - 1) {
				emit_jmp(state, TARGET_PC_EXIT);
			}
			break;

		case EBPF_OP_LDXW:
			emit_load(state, S32, src, dst, inst.offset);
			break;
		case EBPF_OP_LDXH:
			emit_load(state, S16, src, dst, inst.offset);
			break;
		case EBPF_OP_LDXB:
			emit_load(state, S8, src, dst, inst.offset);
			break;
		case EBPF_OP_LDXDW:
			emit_load(state, S64, src, dst, inst.offset);
			break;

		case EBPF_OP_STW:
			emit_store_imm32(state, S32, dst, inst.offset,
					 inst.imm);
			break;
		case EBPF_OP_STH:
			emit_store_imm32(state, S16, dst, inst.offset,
					 inst.imm);
			break;
		case EBPF_OP_STB:
			emit_store_imm32(state, S8, dst, inst.offset, inst.imm);
			break;
		case EBPF_OP_STDW:
			emit_store_imm32(state, S64, dst, inst.offset,
					 inst.imm);
			break;

		case EBPF_OP_STXW:
			emit_store(state, S32, src, dst, inst.offset);
			break;
		case EBPF_OP_STXH:
			emit_store(state, S16, src, dst, inst.offset);
			break;
		case EBPF_OP_STXB:
			emit_store(state, S8, src, dst, inst.offset);
			break;
		case EBPF_OP_STXDW:
			emit_store(state, S64, src, dst, inst.offset);
			break;

		case EBPF_OP_LDDW: {
			struct ebpf_inst inst2 = vm->insts[++i];
			uint64_t imm =
			    (uint32_t)inst.imm | ((uint64_t)inst2.imm << 32);
			emit_load_imm(state, dst, imm);
			break;
		}

		default:
			ebpf_error("Unknown instruction at PC %d: opcode %02x",
				   i, inst.opcode);
			return -1;
		}
	}

	/* Epilogue */
	state->exit_loc = state->offset;

	/* Move register 0 into rax */
	if (map_register(0) != RAX) {
		emit_mov(state, map_register(0), RAX);
	}

	/* Deallocate stack space */
	emit_alu64_imm32(state, 0x81, 0, RSP, STACK_SIZE);

	emit_pop(state, R15);
	emit_pop(state, R14);
	emit_pop(state, R13);
	emit_pop(state, RBX);
	emit_pop(state, RBP);

	emit1(state, 0xc3); /* ret */

	/* Division by zero handler */
	const char *div_by_zero_fmt = "division by zero at PC %u\n";
	state->div_by_zero_loc = state->offset;
	emit_load_imm(state, RDI, (uintptr_t)div_by_zero_fmt);
	emit_mov(state, RCX, RSI); /* muldivmod stored pc in RCX */
	emit_call(state, ebpf_error);
	emit_load_imm(state, map_register(0), -1);
	emit_jmp(state, TARGET_PC_EXIT);

	return 0;
}

static void
muldivmod(struct jit_state *state, uint16_t pc, uint8_t opcode, int src,
	  int dst, int32_t imm)
{
	bool mul =
	    EBPF_ALU_OP(opcode) == EBPF_ALU_OP(EBPF_OP_MUL_IMM);
	bool div =
	    EBPF_ALU_OP(opcode) == EBPF_ALU_OP(EBPF_OP_DIV_IMM);
	bool mod =
	    EBPF_ALU_OP(opcode) == EBPF_ALU_OP(EBPF_OP_MOD_IMM);
	bool is64 = EBPF_CLS(opcode) == EBPF_CLS_ALU64;

	if (div || mod) {
		emit_load_imm(state, RCX, pc);

		/* test src,src */
		if (is64) {
			emit_alu64(state, 0x85, src, src);
		} else {
			emit_alu32(state, 0x85, src, src);
		}

		/* jz div_by_zero */
		emit_jcc(state, 0x84, TARGET_PC_DIV_BY_ZERO);
	}

	if (dst != RAX) {
		emit_push(state, RAX);
	}
	if (dst != RDX) {
		emit_push(state, RDX);
	}
	if (imm) {
		emit_load_imm(state, RCX, imm);
	} else {
		emit_mov(state, src, RCX);
	}

	emit_mov(state, dst, RAX);

	if (div || mod) {
		/* xor %edx,%edx */
		emit_alu32(state, 0x31, RDX, RDX);
	}

	if (is64) {
		emit_rex(state, 1, 0, 0, 0);
	}

	/* mul %ecx or div %ecx */
	emit_alu32(state, 0xf7, mul ? 4 : 6, RCX);

	if (dst != RDX) {
		if (mod) {
			emit_mov(state, RDX, dst);
		}
		emit_pop(state, RDX);
	}
	if (dst != RAX) {
		if (div || mul) {
			emit_mov(state, RAX, dst);
		}
		emit_pop(state, RAX);
	}
}

static void
resolve_jumps(struct ebpf_vm *vm, struct jit_state *state)
{
	int i;
	for (i = 0; i < state->num_jumps; i++) {
		struct jump jump = state->jumps[i];

		int target_loc;
		if (jump.target_pc == TARGET_PC_EXIT) {
			target_loc = state->exit_loc;
		} else if (jump.target_pc == TARGET_PC_DIV_BY_ZERO) {
			target_loc = state->div_by_zero_loc;
		} else {
			target_loc = state->pc_locs[jump.target_pc];
		}

		/* Assumes jump offset is at end of instruction */
		uint32_t rel =
		    target_loc - (jump.offset_loc + sizeof(uint32_t));

		uint8_t *offset_ptr = &state->buf[jump.offset_loc];
		memcpy(offset_ptr, &rel, sizeof(uint32_t));
	}
}

ebpf_jit_fn
ebpf_compile(struct ebpf_vm *vm)
{
	void *jitted = NULL;
	size_t jitted_size;
	struct jit_state state;

	if (vm->jitted) {
		return vm->jitted;
	}

	if (!vm->insts) {
		ebpf_error("code has not been loaded into this VM");
		return NULL;
	}

	state.offset = 0;
	state.size = 65536;
	state.buf = ebpf_calloc(state.size, 1);
	state.pc_locs = ebpf_calloc(MAX_INSTS + 1, sizeof(state.pc_locs[0]));
	state.jumps = ebpf_calloc(MAX_INSTS, sizeof(state.jumps[0]));
	state.num_jumps = 0;

	if (translate(vm, &state) < 0) {
		goto out;
	}

	resolve_jumps(vm, &state);

	jitted_size = state.offset;

	jitted = ebpf_exalloc(jitted_size);
	if (jitted == NULL) {
		ebpf_error("couldn't allocate executable memory\n");
		goto out;
	}

	memcpy(jitted, state.buf, jitted_size);

	vm->jitted = jitted;
	vm->jitted_size = jitted_size;

out:
	ebpf_free(state.buf);
	ebpf_free(state.pc_locs);
	ebpf_free(state.jumps);
	if (jitted && vm->jitted == NULL) {
		ebpf_exfree(jitted, jitted_size);
	}
	return vm->jitted;
}
