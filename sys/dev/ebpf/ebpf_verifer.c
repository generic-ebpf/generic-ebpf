/*
 * Copyright 2015 Big Switch Networks, Inc
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

#include "ebpf_platform.h"
#include "ebpf_internal.h"

/*
 * Minimum code verification. Don't rely on this.
 * This might be replaced and deleted in future commits.
 */
bool
ebpf_validate(const struct ebpf_vm *vm, const struct ebpf_inst *insts,
	      uint32_t num_insts)
{
	if (num_insts >= MAX_INSTS) {
		ebpf_error("too many instructions (max %u)\n", MAX_INSTS);
		return false;
	}

	if (num_insts == 0 || insts[num_insts - 1].opcode != EBPF_OP_EXIT) {
		ebpf_error("no exit at end of instructions\n");
		return false;
	}

	int i;
	for (i = 0; i < num_insts; i++) {
		struct ebpf_inst inst = insts[i];
		bool store = false;

		switch (inst.opcode) {
		case EBPF_OP_ADD_IMM:
		case EBPF_OP_ADD_REG:
		case EBPF_OP_SUB_IMM:
		case EBPF_OP_SUB_REG:
		case EBPF_OP_MUL_IMM:
		case EBPF_OP_MUL_REG:
		case EBPF_OP_DIV_REG:
		case EBPF_OP_OR_IMM:
		case EBPF_OP_OR_REG:
		case EBPF_OP_AND_IMM:
		case EBPF_OP_AND_REG:
		case EBPF_OP_LSH_IMM:
		case EBPF_OP_LSH_REG:
		case EBPF_OP_RSH_IMM:
		case EBPF_OP_RSH_REG:
		case EBPF_OP_NEG:
		case EBPF_OP_MOD_REG:
		case EBPF_OP_XOR_IMM:
		case EBPF_OP_XOR_REG:
		case EBPF_OP_MOV_IMM:
		case EBPF_OP_MOV_REG:
		case EBPF_OP_ARSH_IMM:
		case EBPF_OP_ARSH_REG:
			break;

		case EBPF_OP_LE:
		case EBPF_OP_BE:
			if (inst.imm != 16 && inst.imm != 32 &&
			    inst.imm != 64) {
				ebpf_error(
				    "invalid endian immediate at PC %d\n", i);
				return false;
			}
			break;

		case EBPF_OP_ADD64_IMM:
		case EBPF_OP_ADD64_REG:
		case EBPF_OP_SUB64_IMM:
		case EBPF_OP_SUB64_REG:
		case EBPF_OP_MUL64_IMM:
		case EBPF_OP_MUL64_REG:
		case EBPF_OP_DIV64_REG:
		case EBPF_OP_OR64_IMM:
		case EBPF_OP_OR64_REG:
		case EBPF_OP_AND64_IMM:
		case EBPF_OP_AND64_REG:
		case EBPF_OP_LSH64_IMM:
		case EBPF_OP_LSH64_REG:
		case EBPF_OP_RSH64_IMM:
		case EBPF_OP_RSH64_REG:
		case EBPF_OP_NEG64:
		case EBPF_OP_MOD64_REG:
		case EBPF_OP_XOR64_IMM:
		case EBPF_OP_XOR64_REG:
		case EBPF_OP_MOV64_IMM:
		case EBPF_OP_MOV64_REG:
		case EBPF_OP_ARSH64_IMM:
		case EBPF_OP_ARSH64_REG:
			break;

		case EBPF_OP_LDXW:
		case EBPF_OP_LDXH:
		case EBPF_OP_LDXB:
		case EBPF_OP_LDXDW:
			break;

		case EBPF_OP_STW:
		case EBPF_OP_STH:
		case EBPF_OP_STB:
		case EBPF_OP_STDW:
		case EBPF_OP_STXW:
		case EBPF_OP_STXH:
		case EBPF_OP_STXB:
		case EBPF_OP_STXDW:
			store = true;
			break;

		case EBPF_OP_LDDW:
			if (i + 1 >= num_insts || insts[i + 1].opcode != 0) {
				ebpf_error("incomplete lddw at PC %d\n", i);
				return false;
			}
			i++; /* Skip next instruction */
			break;

		case EBPF_OP_JA:
		case EBPF_OP_JEQ_REG:
		case EBPF_OP_JEQ_IMM:
		case EBPF_OP_JGT_REG:
		case EBPF_OP_JGT_IMM:
		case EBPF_OP_JGE_REG:
		case EBPF_OP_JGE_IMM:
		case EBPF_OP_JLT_REG:
		case EBPF_OP_JLT_IMM:
		case EBPF_OP_JLE_REG:
		case EBPF_OP_JLE_IMM:
		case EBPF_OP_JSET_REG:
		case EBPF_OP_JSET_IMM:
		case EBPF_OP_JNE_REG:
		case EBPF_OP_JNE_IMM:
		case EBPF_OP_JSGT_IMM:
		case EBPF_OP_JSGT_REG:
		case EBPF_OP_JSGE_IMM:
		case EBPF_OP_JSGE_REG:
		case EBPF_OP_JSLT_IMM:
		case EBPF_OP_JSLT_REG:
		case EBPF_OP_JSLE_IMM:
		case EBPF_OP_JSLE_REG:
			if (inst.offset == -1) {
				ebpf_error("infinite loop at PC %d\n", i);
				return false;
			}
			int new_pc = i + 1 + inst.offset;
			if (new_pc < 0 || new_pc >= num_insts) {
				ebpf_error("jump out of bounds at PC %d\n", i);
				return false;
			} else if (insts[new_pc].opcode == 0) {
				ebpf_error("jump to middle of lddw at PC %d\n",
					   i);
				return false;
			}
			break;

		case EBPF_OP_CALL:
			if (inst.imm < 0 || inst.imm >= MAX_EXT_FUNCS) {
				ebpf_error("invalid call immediate at PC %d\n",
					   i);
				return false;
			}
			if (!vm->ext_funcs[inst.imm]) {
				ebpf_error("call to nonexistent function %u at "
					   "PC %d\n",
					   inst.imm, i);
				return false;
			}
			break;

		case EBPF_OP_EXIT:
			break;

		case EBPF_OP_DIV_IMM:
		case EBPF_OP_MOD_IMM:
		case EBPF_OP_DIV64_IMM:
		case EBPF_OP_MOD64_IMM:
			if (inst.imm == 0) {
				ebpf_error("division by zero at PC %d\n", i);
				return false;
			}
			break;

		default:
			ebpf_error("unknown opcode 0x%02x at PC %d\n",
				   inst.opcode, i);
			return false;
		}

		if (inst.src > 10) {
			ebpf_error("invalid source register at PC %d\n", i);
			return false;
		}

		if (inst.dst > 9 && !(store && inst.dst == 10)) {
			ebpf_error("invalid destination register at PC %d\n",
				   i);
			return false;
		}
	}

	return true;
}
