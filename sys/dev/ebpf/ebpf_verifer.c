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

#include "ebpf_os.h"
#include "ebpf_int.h"

/*
 * Verifer Stage1
 *
 * Scan eBPF program with iterative DFS
 *
 * detects
 * - backward jump
 * - unreachable instruction
 */

enum {
    NOT_VISITED = 0,
    VISITED
};

static bool
is_invalid_jmp(const struct ebpf_inst *insts, int *inst_visited,
    int cur, int next, uint32_t num_insts)
{
    if (next >= num_insts) {
        ebpf_error("jump out of bounds at PC %d", cur);
        return true;
    } else if (inst_visited[next] == VISITED) {
        ebpf_error("back-edge detected");
        return true;
    } else if (insts[next].opcode == 0) {
        ebpf_error("jump to middle of lddw at PC %d", cur);
        return true;
    }

    return false;
}

#define MAX_INST_COMPLEXITY 1024

static int
verifer_stage1(const struct ebpf_inst *insts, uint32_t num_insts)
{
    if (insts == NULL || num_insts == 0) {
        return -EINVAL;
    }

    int ret;
    uint32_t *stack;
    uint32_t stack_ptr;
    int *inst_visited;

    stack = ebpf_calloc(sizeof(uint32_t), MAX_INST_COMPLEXITY + 1);
    if (stack == NULL) {
        return -ENOMEM;
    }

    inst_visited = ebpf_calloc(sizeof(int), num_insts);
    if (inst_visited == NULL) {
        ebpf_free(stack);
        return -ENOMEM;
    }

    stack[0] = 0;
    stack_ptr = 1;

    while (stack_ptr > 0) {
        uint32_t cur = stack[--stack_ptr];
        uint8_t op = insts[cur].opcode;
        uint8_t cls = EBPF_CLS(op);

        if (stack_ptr > MAX_INST_COMPLEXITY) {
            ebpf_error("exceeded complexity limit");
            ret = -EINVAL;
            goto err;
        }

        if (cls == EBPF_CLS_JMP) {
            uint32_t next;
            if (op == EBPF_OP_EXIT) {
                // do nothing
            } else if (op == EBPF_OP_CALL) {
                next = cur + 1;
                stack[stack_ptr++] = cur + 1;
            } else if (op == EBPF_OP_JA) {
                // unconditional jump
                next = cur + insts[cur].offset + 1;
                if (is_invalid_jmp(insts, inst_visited,
                            cur, next, num_insts)) {
                    ret = -EINVAL;
                    goto err;
                }
                stack[stack_ptr++] = next;
            } else {
                // conditional jump
                next = cur + insts[cur].offset + 1;
                if (is_invalid_jmp(insts, inst_visited,
                            cur, next, num_insts)) {
                    ret = -EINVAL;
                    goto err;
                }
                stack[stack_ptr++] = next;

                next = cur + 1;
                if (is_invalid_jmp(insts, inst_visited,
                            cur, next, num_insts)) {
                    ret = -EINVAL;
                    goto err;
                }
                stack[stack_ptr++] = next;
            }
        } else {
            // check opcode range
            if (cls > EBPF_CLS_ALU64) {
                ebpf_error("invalid opcode class");
                ret = -EINVAL;
                goto err;
            }

            stack[stack_ptr++] = cur + 1;
        }

        inst_visited[cur] = VISITED;
    }

    for (uint32_t i = 0; i < num_insts; i++) {
        if (inst_visited[i] == NOT_VISITED) {
            ebpf_error("unreachable instruction at %u", i);
            ret = -EINVAL;
            goto err;
        }
    }

    ret = 0;

err:
    ebpf_free(stack);
    ebpf_free(inst_visited);
    return ret;
}

int
ebpf_validate(const struct ebpf_vm *vm, const struct ebpf_inst *insts, uint32_t num_insts)
{
    int err;

    if (num_insts >= MAX_INSTS) {
        ebpf_error("too many instructions (max %u)", MAX_INSTS);
        return -EINVAL;
    }

    err = verifer_stage1(insts, num_insts);
    if (err < 0) {
      return err;
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
            if (inst.imm != 16 && inst.imm != 32 && inst.imm != 64) {
                ebpf_error("invalid endian immediate at PC %d", i);
                return -EINVAL;
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
            if (i + 1 >= num_insts || insts[i+1].opcode != 0) {
                ebpf_error("incomplete lddw at PC %d", i);
                return -EINVAL;
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
        case EBPF_OP_JSET_REG:
        case EBPF_OP_JSET_IMM:
        case EBPF_OP_JNE_REG:
        case EBPF_OP_JNE_IMM:
        case EBPF_OP_JSGT_IMM:
        case EBPF_OP_JSGT_REG:
        case EBPF_OP_JSGE_IMM:
        case EBPF_OP_JSGE_REG:
            break;

        case EBPF_OP_CALL:
            if (inst.imm < 0 || inst.imm >= MAX_EXT_FUNCS) {
                ebpf_error("invalid call immediate at PC %d", i);
                return -EINVAL;
            }
            if (!vm->ext_funcs[inst.imm]) {
                ebpf_error("call to nonexistent function %u at PC %d", inst.imm, i);
                return -EINVAL;
            }
            break;

        case EBPF_OP_EXIT:
            break;

        case EBPF_OP_DIV_IMM:
        case EBPF_OP_MOD_IMM:
        case EBPF_OP_DIV64_IMM:
        case EBPF_OP_MOD64_IMM:
            if (inst.imm == 0) {
                ebpf_error("division by zero at PC %d", i);
                return -EINVAL;
            }
            break;

        default:
            ebpf_error("unknown opcode 0x%02x at PC %d", inst.opcode, i);
            return -EINVAL;
        }

        if (inst.src > 10) {
            ebpf_error("invalid source register at PC %d", i);
            return -EINVAL;
        }

        if (inst.dst > 9 && !(store && inst.dst == 10)) {
            ebpf_error("invalid destination register at PC %d", i);
            return -EINVAL;
        }
    }

    return 0;
}
