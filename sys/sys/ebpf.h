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

#pragma once

struct ebpf_vm;

enum ebpf_prog_types {
  EBPF_PROG_TYPE_TEST = 0,
  __EBPF_PROG_TYPE_MAX
};

enum ebpf_map_types {
  EBPF_MAP_TYPE_NULL = 0,
  __EBPF_MAP_TYPE_MAX
};

union ebpf_req {
  // Attribute of EBPFIOC_LOAD_PROG
  struct {
    int *prog_fdp;
    uint16_t prog_type;
    uint32_t prog_len;
    void *prog;
  };
  // Attribute of EBPFIOC_MAP_CREATE
  struct {
    int *map_fdp;
    uint32_t map_type;
    uint32_t key_size;
    uint32_t value_size;
    uint32_t max_entries;
    uint32_t map_flags;
  };
  // Attribute of EBPFIOC_MAP_*_ELEM and EBPFIOC_MAP_GET_*_KEY
  struct {
    int map_fd;
    uint64_t key;
    union {
      uint64_t value;
      uint64_t next_key;
    };
    uint64_t flags;
  };
};

typedef uint64_t (*ebpf_jit_fn)(void *mem, size_t mem_len);

struct ebpf_vm *ebpf_create(void);
void ebpf_destroy(struct ebpf_vm *vm);

/*
 * Register an external function
 *
 * The immediate field of a CALL instruction is an index into an array of
 * functions registered by the user. This API associates a function with
 * an index.
 *
 * 'name' should be a string with a lifetime longer than the VM.
 *
 * Returns 0 on success, -1 on error.
 */
int ebpf_register(struct ebpf_vm *vm, unsigned int idx, const char *name,
                  void *fn);

/*
 * Load code into a VM
 *
 * This must be done before calling ebpf_exec or ebpf_compile and after
 * registering all functions.
 *
 * 'code' should point to eBPF bytecodes and 'code_len' should be the size in
 * bytes of that buffer.
 *
 * Returns 0 on success, -1 on error.
 */
int ebpf_load(struct ebpf_vm *vm, const void *code, uint32_t code_len);

/*
 * Load code from an ELF binary
 *
 * This must be done before calling ebpf_exec or ebpf_compile and after
 * registering all functions.
 *
 * 'elf' should point to a copy of an ELF file in memory and 'elf_len' should
 * be the size in bytes of that buffer.
 *
 * The ELF binary must be 64-bit little-endian with a single text section
 * containing the eBPF bytecodes. This is compatible with the output of
 * Clang.
 *
 * Returns 0 on success, -1 on error.
 */
int ebpf_load_elf(struct ebpf_vm *vm, const void *elf, size_t elf_len);

uint64_t ebpf_exec(const struct ebpf_vm *vm, void *mem, size_t mem_len);
uint64_t ebpf_exec_jit(const struct ebpf_vm *vm, void *mem, size_t mem_len);

ebpf_jit_fn ebpf_compile(struct ebpf_vm *vm);

/* eBPF definitions */

struct ebpf_inst {
    uint8_t opcode;
    uint8_t dst : 4;
    uint8_t src : 4;
    int16_t offset;
    int32_t imm;
};

#define EBPF_CLS_MASK 0x07
#define EBPF_CLS(op) (op & EBPF_CLS_MASK)

#define EBPF_ALU_OP_MASK 0xf0

#define EBPF_CLS_LD 0x00
#define EBPF_CLS_LDX 0x01
#define EBPF_CLS_ST 0x02
#define EBPF_CLS_STX 0x03
#define EBPF_CLS_ALU 0x04
#define EBPF_CLS_JMP 0x05
#define EBPF_CLS_ALU64 0x07

#define EBPF_SRC_IMM 0x00
#define EBPF_SRC_REG 0x08

#define EBPF_SIZE_W 0x00
#define EBPF_SIZE_H 0x08
#define EBPF_SIZE_B 0x10
#define EBPF_SIZE_DW 0x18

/* Other memory modes are not yet supported */
#define EBPF_MODE_IMM 0x00
#define EBPF_MODE_MEM 0x60

#define EBPF_OP_ADD_IMM (EBPF_CLS_ALU | EBPF_SRC_IMM | 0x00)
#define EBPF_OP_ADD_REG (EBPF_CLS_ALU | EBPF_SRC_REG | 0x00)
#define EBPF_OP_SUB_IMM (EBPF_CLS_ALU | EBPF_SRC_IMM | 0x10)
#define EBPF_OP_SUB_REG (EBPF_CLS_ALU | EBPF_SRC_REG | 0x10)
#define EBPF_OP_MUL_IMM (EBPF_CLS_ALU | EBPF_SRC_IMM | 0x20)
#define EBPF_OP_MUL_REG (EBPF_CLS_ALU | EBPF_SRC_REG | 0x20)
#define EBPF_OP_DIV_IMM (EBPF_CLS_ALU | EBPF_SRC_IMM | 0x30)
#define EBPF_OP_DIV_REG (EBPF_CLS_ALU | EBPF_SRC_REG | 0x30)
#define EBPF_OP_OR_IMM (EBPF_CLS_ALU | EBPF_SRC_IMM | 0x40)
#define EBPF_OP_OR_REG (EBPF_CLS_ALU | EBPF_SRC_REG | 0x40)
#define EBPF_OP_AND_IMM (EBPF_CLS_ALU | EBPF_SRC_IMM | 0x50)
#define EBPF_OP_AND_REG (EBPF_CLS_ALU | EBPF_SRC_REG | 0x50)
#define EBPF_OP_LSH_IMM (EBPF_CLS_ALU | EBPF_SRC_IMM | 0x60)
#define EBPF_OP_LSH_REG (EBPF_CLS_ALU | EBPF_SRC_REG | 0x60)
#define EBPF_OP_RSH_IMM (EBPF_CLS_ALU | EBPF_SRC_IMM | 0x70)
#define EBPF_OP_RSH_REG (EBPF_CLS_ALU | EBPF_SRC_REG | 0x70)
#define EBPF_OP_NEG (EBPF_CLS_ALU | 0x80)
#define EBPF_OP_MOD_IMM (EBPF_CLS_ALU | EBPF_SRC_IMM | 0x90)
#define EBPF_OP_MOD_REG (EBPF_CLS_ALU | EBPF_SRC_REG | 0x90)
#define EBPF_OP_XOR_IMM (EBPF_CLS_ALU | EBPF_SRC_IMM | 0xa0)
#define EBPF_OP_XOR_REG (EBPF_CLS_ALU | EBPF_SRC_REG | 0xa0)
#define EBPF_OP_MOV_IMM (EBPF_CLS_ALU | EBPF_SRC_IMM | 0xb0)
#define EBPF_OP_MOV_REG (EBPF_CLS_ALU | EBPF_SRC_REG | 0xb0)
#define EBPF_OP_ARSH_IMM (EBPF_CLS_ALU | EBPF_SRC_IMM | 0xc0)
#define EBPF_OP_ARSH_REG (EBPF_CLS_ALU | EBPF_SRC_REG | 0xc0)
#define EBPF_OP_LE (EBPF_CLS_ALU | EBPF_SRC_IMM | 0xd0)
#define EBPF_OP_BE (EBPF_CLS_ALU | EBPF_SRC_REG | 0xd0)

#define EBPF_OP_ADD64_IMM (EBPF_CLS_ALU64 | EBPF_SRC_IMM | 0x00)
#define EBPF_OP_ADD64_REG (EBPF_CLS_ALU64 | EBPF_SRC_REG | 0x00)
#define EBPF_OP_SUB64_IMM (EBPF_CLS_ALU64 | EBPF_SRC_IMM | 0x10)
#define EBPF_OP_SUB64_REG (EBPF_CLS_ALU64 | EBPF_SRC_REG | 0x10)
#define EBPF_OP_MUL64_IMM (EBPF_CLS_ALU64 | EBPF_SRC_IMM | 0x20)
#define EBPF_OP_MUL64_REG (EBPF_CLS_ALU64 | EBPF_SRC_REG | 0x20)
#define EBPF_OP_DIV64_IMM (EBPF_CLS_ALU64 | EBPF_SRC_IMM | 0x30)
#define EBPF_OP_DIV64_REG (EBPF_CLS_ALU64 | EBPF_SRC_REG | 0x30)
#define EBPF_OP_OR64_IMM (EBPF_CLS_ALU64 | EBPF_SRC_IMM | 0x40)
#define EBPF_OP_OR64_REG (EBPF_CLS_ALU64 | EBPF_SRC_REG | 0x40)
#define EBPF_OP_AND64_IMM (EBPF_CLS_ALU64 | EBPF_SRC_IMM | 0x50)
#define EBPF_OP_AND64_REG (EBPF_CLS_ALU64 | EBPF_SRC_REG | 0x50)
#define EBPF_OP_LSH64_IMM (EBPF_CLS_ALU64 | EBPF_SRC_IMM | 0x60)
#define EBPF_OP_LSH64_REG (EBPF_CLS_ALU64 | EBPF_SRC_REG | 0x60)
#define EBPF_OP_RSH64_IMM (EBPF_CLS_ALU64 | EBPF_SRC_IMM | 0x70)
#define EBPF_OP_RSH64_REG (EBPF_CLS_ALU64 | EBPF_SRC_REG | 0x70)
#define EBPF_OP_NEG64 (EBPF_CLS_ALU64 | 0x80)
#define EBPF_OP_MOD64_IMM (EBPF_CLS_ALU64 | EBPF_SRC_IMM | 0x90)
#define EBPF_OP_MOD64_REG (EBPF_CLS_ALU64 | EBPF_SRC_REG | 0x90)
#define EBPF_OP_XOR64_IMM (EBPF_CLS_ALU64 | EBPF_SRC_IMM | 0xa0)
#define EBPF_OP_XOR64_REG (EBPF_CLS_ALU64 | EBPF_SRC_REG | 0xa0)
#define EBPF_OP_MOV64_IMM (EBPF_CLS_ALU64 | EBPF_SRC_IMM | 0xb0)
#define EBPF_OP_MOV64_REG (EBPF_CLS_ALU64 | EBPF_SRC_REG | 0xb0)
#define EBPF_OP_ARSH64_IMM (EBPF_CLS_ALU64 | EBPF_SRC_IMM | 0xc0)
#define EBPF_OP_ARSH64_REG (EBPF_CLS_ALU64 | EBPF_SRC_REG | 0xc0)

#define EBPF_OP_LDXW (EBPF_CLS_LDX | EBPF_MODE_MEM | EBPF_SIZE_W)
#define EBPF_OP_LDXH (EBPF_CLS_LDX | EBPF_MODE_MEM | EBPF_SIZE_H)
#define EBPF_OP_LDXB (EBPF_CLS_LDX | EBPF_MODE_MEM | EBPF_SIZE_B)
#define EBPF_OP_LDXDW (EBPF_CLS_LDX | EBPF_MODE_MEM | EBPF_SIZE_DW)
#define EBPF_OP_STW (EBPF_CLS_ST | EBPF_MODE_MEM | EBPF_SIZE_W)
#define EBPF_OP_STH (EBPF_CLS_ST | EBPF_MODE_MEM | EBPF_SIZE_H)
#define EBPF_OP_STB (EBPF_CLS_ST | EBPF_MODE_MEM | EBPF_SIZE_B)
#define EBPF_OP_STDW (EBPF_CLS_ST | EBPF_MODE_MEM | EBPF_SIZE_DW)
#define EBPF_OP_STXW (EBPF_CLS_STX | EBPF_MODE_MEM | EBPF_SIZE_W)
#define EBPF_OP_STXH (EBPF_CLS_STX | EBPF_MODE_MEM | EBPF_SIZE_H)
#define EBPF_OP_STXB (EBPF_CLS_STX | EBPF_MODE_MEM | EBPF_SIZE_B)
#define EBPF_OP_STXDW (EBPF_CLS_STX | EBPF_MODE_MEM | EBPF_SIZE_DW)
#define EBPF_OP_LDDW (EBPF_CLS_LD | EBPF_MODE_IMM | EBPF_SIZE_DW)

#define EBPF_OP_JA (EBPF_CLS_JMP | 0x00)
#define EBPF_OP_JEQ_IMM (EBPF_CLS_JMP | EBPF_SRC_IMM | 0x10)
#define EBPF_OP_JEQ_REG (EBPF_CLS_JMP | EBPF_SRC_REG | 0x10)
#define EBPF_OP_JGT_IMM (EBPF_CLS_JMP | EBPF_SRC_IMM | 0x20)
#define EBPF_OP_JGT_REG (EBPF_CLS_JMP | EBPF_SRC_REG | 0x20)
#define EBPF_OP_JGE_IMM (EBPF_CLS_JMP | EBPF_SRC_IMM | 0x30)
#define EBPF_OP_JGE_REG (EBPF_CLS_JMP | EBPF_SRC_REG | 0x30)
#define EBPF_OP_JSET_REG (EBPF_CLS_JMP | EBPF_SRC_REG | 0x40)
#define EBPF_OP_JSET_IMM (EBPF_CLS_JMP | EBPF_SRC_IMM | 0x40)
#define EBPF_OP_JNE_IMM (EBPF_CLS_JMP | EBPF_SRC_IMM | 0x50)
#define EBPF_OP_JNE_REG (EBPF_CLS_JMP | EBPF_SRC_REG | 0x50)
#define EBPF_OP_JSGT_IMM (EBPF_CLS_JMP | EBPF_SRC_IMM | 0x60)
#define EBPF_OP_JSGT_REG (EBPF_CLS_JMP | EBPF_SRC_REG | 0x60)
#define EBPF_OP_JSGE_IMM (EBPF_CLS_JMP | EBPF_SRC_IMM | 0x70)
#define EBPF_OP_JSGE_REG (EBPF_CLS_JMP | EBPF_SRC_REG | 0x70)
#define EBPF_OP_CALL (EBPF_CLS_JMP | 0x80)
#define EBPF_OP_EXIT (EBPF_CLS_JMP | 0x90)

#define EBPF_OP_JLT_IMM (EBPF_CLS_JMP|EBPF_SRC_IMM|0xa0)
#define EBPF_OP_JLT_REG (EBPF_CLS_JMP|EBPF_SRC_REG|0xa0)
#define EBPF_OP_JLE_IMM (EBPF_CLS_JMP|EBPF_SRC_IMM|0xb0)
#define EBPF_OP_JLE_REG (EBPF_CLS_JMP|EBPF_SRC_REG|0xb0)
#define EBPF_OP_JSLT_IMM (EBPF_CLS_JMP|EBPF_SRC_IMM|0xc0)
#define EBPF_OP_JSLT_REG (EBPF_CLS_JMP|EBPF_SRC_REG|0xc0)
#define EBPF_OP_JSLE_IMM (EBPF_CLS_JMP|EBPF_SRC_IMM|0xd0)
#define EBPF_OP_JSLE_REG (EBPF_CLS_JMP|EBPF_SRC_REG|0xd0)
