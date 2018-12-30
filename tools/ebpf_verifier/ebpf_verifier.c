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

#include <dev/ebpf/ebpf_platform.h>
#include <sys/ebpf_inst.h>

#include "ebpf_disassembler.h"

struct ebpf_visitor;

typedef int (*accept_fn)(struct ebpf_visitor *v);

struct inst_edge {
	bool passed;
	uint16_t idx;
};

struct inst_node {
	bool discovered;
	uint8_t nedges;
	struct inst_edge edges[2];
};

enum ebpf_reg_type {
	NOT_INIT,
	SCALAR_VALUE,
	PTR_TO_CTX,
	PTR_TO_MAP_VALUE,
	PTR_TO_MAP_VALUE_OR_NULL,
	PTR_TO_STACK
};

const char *reg_type_str[] = {
	[NOT_INIT] = "not_init",
	[SCALAR_VALUE] = "scalar_value",
	[PTR_TO_CTX] = "ptr_to_ctx",
	[PTR_TO_MAP_VALUE] = "ptr_to_map_value",
	[PTR_TO_MAP_VALUE_OR_NULL] = "ptr_to_map_value_or_null",
	[PTR_TO_STACK] = "ptr_to_stack"
};

struct reg_state {
	enum ebpf_reg_type type;
	int64_t smax;
	int64_t smin;
	uint64_t umax;
	uint64_t umin;
};

struct ebpf_verifier {
	uint16_t ninsts;
	struct ebpf_inst *insts;
	struct inst_node *nodes;
	struct reg_state reg_states[11];

	struct {
		uint16_t *cur;
		uint16_t *start;
		uint16_t *end;
	} stack;

	FILE *out_file;
	FILE *dot_file;
};

/*
 * FIXME: Be more generic
 */
static bool
is_pointer_type(struct ebpf_verifier *v, uint8_t reg_id)
{
	switch (v->reg_states[reg_id].type) {
		case NOT_INIT:
		case SCALAR_VALUE:
			return false;
		case PTR_TO_CTX:
		case PTR_TO_MAP_VALUE:
		case PTR_TO_MAP_VALUE_OR_NULL:
		case PTR_TO_STACK:
			return true;
	}
}

static void
print_verifier_state(struct ebpf_verifier *v, struct ebpf_inst *inst)
{
	char *fmt;

	fprintf(v->out_file, "{\"cur_inst\": \"");
	print_inst(inst, v->out_file);
	fprintf(v->out_file, "\",\n \"registers\": [\n");
	for (uint16_t i = 0; i < 11; i++) {
		if (i == 10) {
			fmt = "{\"type\": \"%s\",\"smax\":%ld,\"smin\":%ld,\"umax\":%lu,\"umin\":%lu}\n";
		} else {
			fmt = "{\"type\": \"%s\",\"smax\":%ld,\"smin\":%ld,\"umax\":%lu,\"umin\":%lu},\n";
		}

		fprintf(v->out_file, fmt,
				reg_type_str[v->reg_states[i].type],
				v->reg_states[i].smax,
				v->reg_states[i].smin,
				v->reg_states[i].umax,
				v->reg_states[i].umin
		);
	}
	fprintf(v->out_file, "]}\n");
}

static inline int
stack_init(struct ebpf_verifier *v)
{
	v->stack.start =
		calloc(sizeof(*v->stack.start), v->ninsts);
	if (v->stack.start == NULL) {
		return ENOMEM;
	}

	v->stack.cur = v->stack.start;
	v->stack.end = v->stack.start + v->ninsts;

	return 0;
}

static inline void
stack_deinit(struct ebpf_verifier *v)
{
	free(v->stack.start);
}

static inline bool
stack_empty(struct ebpf_verifier *v)
{
	return v->stack.cur == v->stack.start;
}

static inline int
stack_push(struct ebpf_verifier *v, uint16_t val)
{
	if (v->stack.cur == v->stack.end) {
		return E2BIG;
	}

	*v->stack.cur++ = val;
	return 0;
}

static inline int
stack_pop(struct ebpf_verifier *v, uint16_t *val)
{
	if (stack_empty(v)) {
		return ENOENT;
	}

	*val = *--v->stack.cur;
	return 0;
}

static void
init_registers(struct ebpf_verifier *v)
{
	for (uint8_t i = 0; i < 11; i++) {
		if (i == 1) {
			v->reg_states[i].type = PTR_TO_CTX;
		} else if (i == 10) {
			v->reg_states[i].type = PTR_TO_STACK;
		} else {
			v->reg_states[i].type = NOT_INIT;
		}

		v->reg_states[i].smax = INT64_MAX;
		v->reg_states[i].smin = INT64_MIN;
		v->reg_states[i].umax = UINT64_MAX;
		v->reg_states[i].umin = 0;
	}
}

static int
check_syntax_common(struct ebpf_verifier *v, struct ebpf_inst *inst)
{
	uint8_t cls = EBPF_CLS(inst->opcode);

	/* check register id */
	if (inst->dst > EBPF_REG_MAX || inst->src > EBPF_REG_MAX) {
		return EINVAL;
	}

	/* check opcode class id */
	if (cls > EBPF_CLS_ALU64) {
		return EINVAL;
	}

	return 0;
}

static int
check_syntax_ld(struct ebpf_verifier *v, struct ebpf_inst *inst)
{
	uint8_t mode = EBPF_MODE(inst->opcode);

	if (mode == EBPF_MODE_IMM) {
		if (inst->opcode != EBPF_OP_LDDW) {
			printf("Unknown opcode\n");
			return EINVAL;
		}

		/* LDDW case */
		if ((inst->src != EBPF_PSEUDO_MAP_DESC && inst->src != 0)
				|| inst->offset != 0) {
			printf("Invalid lddw format\n");
			return EINVAL;
		}

		/* LDDW consumes 2 instructions. Check next instruction syntax */
		struct ebpf_inst *next = inst + 1;
		if (next > v->insts + v->ninsts) {
			printf("Imcomplete lddw format\n");
			return EINVAL;
		}

		if (next->opcode != 0 || next->src != 0 ||
				next->dst != 0 || next->offset != 0) {
			printf("Invalid lddw format\n");
			return EINVAL;
		}
	} else if (mode == EBPF_MODE_MEM) {
		if (inst->imm != 0) {
			printf("Syntax Error: LD instruction uses reserved field\n");
			return EINVAL;
		}
	} else {
		printf("Unsupported memory mode\n");
		return EINVAL;
	}

	return 0;
}

static int
check_syntax_st(struct ebpf_verifier *v, struct ebpf_inst *inst)
{
	uint8_t mode = EBPF_MODE(inst->opcode);

	if (mode == EBPF_MODE_MEM) {
		if (inst->imm != 0) {
			printf("Syntax Error: ST instruction uses reserved field\n");
			return EINVAL;
		}
	} else {
		printf("Syntax Error: Unsupported memory mode\n");
		return EINVAL;
	}

	return 0;
}

static int
check_syntax_alu(struct ebpf_verifier *v, struct ebpf_inst *inst)
{
	uint8_t opcode = EBPF_ALU_OP(inst->opcode);
	uint8_t source = EBPF_SRC(inst->opcode);

	if (opcode > EBPF_END) {
		printf("Syntax Error: Unknown ALU opcode %u", opcode);
		return EINVAL;
	}

	if (inst->offset != 0) {
		printf("Syntax Error: ALU instruction uses reserved field\n");
		return EINVAL;
	}

	/* 
	 * NEG instruction should meet following requirements.
	 * 1. source == EBPF_SRC_IMM
	 * 2. inst->src == 0
	 * 3. inst->offset == 0
	 * 4. inst->imm == 0
	 *
	 * 3 is already checked, so check 1, 2 and 4 in here.
	 */
	if (opcode == EBPF_NEG) {
		if (source != EBPF_SRC_IMM || inst->src != 0 ||
				inst->imm != 0) {
			printf("Syntax Error: NEG instruction uses reserved field\n");
			return EINVAL;
		}
		return 0;
	}

	/*
	 * END instruction should meet following requirements.
	 * 1. source == EBPF_SRC_IMM
	 * 2. inst->src == 0
	 * 3. inst->offset == 0
	 * 4. inst->imm == 16, 32 or 64
	 * 5. class == BPF_ALU
	 *
	 * 3 is already checkedm so check 1, 2 and 4 in here
	 */
	if (opcode == EBPF_END) {
		if (source != EBPF_SRC_IMM || inst->src != 0 ||
				(inst->imm != 16 && inst->imm != 32 && inst->imm != 64) ||
				EBPF_CLS(inst->opcode) == EBPF_CLS_ALU64) {
			printf("Syntax Error: END instruction uses reserved field\n");
			return EINVAL;
		}
		return 0;
	}

	if (opcode == EBPF_ARSH && EBPF_CLS(inst->opcode) != EBPF_CLS_ALU64) {
		printf("Syntax Error: ARSH is not supported for 32bit ALU\n");
		return EINVAL;
	}

	/*
	 * Check for negative direction shift and over shift
	 */
	if ((opcode == EBPF_LSH || opcode == EBPF_RSH ||
			opcode == EBPF_ARSH) && source == EBPF_SRC_IMM) {
		int32_t size = EBPF_CLS(inst->opcode) == EBPF_CLS_ALU64 ? 64 : 32;
		if (inst->imm < 0 || inst->imm >= size) {
			printf("Syntax Error: Invalid shift %d\n", inst->imm);
			return EINVAL;
		}
	}

	/*
	 * Rest of the ALU instructions
	 */
	if (source == EBPF_SRC_IMM) {
		if (inst->src != 0) {
			printf("Syntax Error: ALU instruction uses reserved field\n");
			return EINVAL;
		}
	} else /* source == EBPF_SRC_REG */ {
		if (inst->imm != 0) {
			printf("Syntax Error: ALU instruction uses reserved field\n");
			return EINVAL;
		}
	}

	return 0;
}

static int
check_type_alu(struct ebpf_verifier *v, struct ebpf_inst *inst)
{
	uint8_t opcode = EBPF_ALU_OP(inst->opcode);
	uint8_t source = EBPF_SRC(inst->opcode);
	struct reg_state *regs = v->reg_states;

	if (opcode == EBPF_NEG || opcode == EBPF_END) {
		if (regs[inst->dst].type == NOT_INIT) {
			printf("Invalid arithmetic operation to uninit value\n");
			return EINVAL;
		}

		if (inst->dst == 10) {
			printf("Frame pointer is read only\n");
			return EINVAL;
		}

		if (is_pointer_type(v, inst->dst)) {
			printf("Invalid destination register type\n");
			return EINVAL;
		}

		return 0;
	}

	if (opcode == EBPF_MOV) {
		if (source == EBPF_SRC_REG &&
			regs[inst->src].type == NOT_INIT) {
			printf("Invalid operation to uninit value\n");
			return EINVAL;
		}
		return 0;
	}

	if (source == EBPF_SRC_IMM) {
		if (regs[inst->dst].type == NOT_INIT) {
			printf("Invalid operation to uninit value\n");
			return EINVAL;
		}
	} else /* source == EBPF_SRC_REG */ {
		if (regs[inst->dst].type == NOT_INIT ||
				regs[inst->src].type == NOT_INIT) {
			printf("Invalid operation to uninit value\n");
			return EINVAL;
		}
	}

	return 0;
}

static int
simulate_alu(struct ebpf_verifier *v, struct ebpf_inst *inst)
{
	uint8_t opcode = EBPF_ALU_OP(inst->opcode);
	uint8_t source = EBPF_SRC(inst->opcode);
	struct reg_state *reg = v->reg_states;

	if (opcode == EBPF_MOV) {
		if (source == EBPF_SRC_IMM) {
			reg[inst->dst].type = SCALAR_VALUE;
			if (EBPF_CLS(inst->opcode) == EBPF_CLS_ALU64) {
				reg[inst->dst].smax = inst->imm;
				reg[inst->dst].smin = inst->imm;
				reg[inst->dst].umax = inst->imm;
				reg[inst->dst].umin = inst->imm;
			} else {
				reg[inst->dst].smax = (uint32_t)inst->imm;
				reg[inst->dst].smin = (uint32_t)inst->imm;
				reg[inst->dst].umax = (uint32_t)inst->imm;
				reg[inst->dst].umin = (uint32_t)inst->imm;
			}
		} else {
			reg[inst->dst] = reg[inst->src];
		}
		return 0;
	}

	// TODO Implement rest of the logic

	return 0;
}

static int
check_syntax_jmp(struct ebpf_verifier *v, struct ebpf_inst *inst)
{
	uint8_t opcode = EBPF_JMP_OP(inst->opcode);
	uint8_t source = EBPF_SRC(inst->opcode);

	if (opcode > EBPF_JSLE) {
		printf("Syntax Error: Unknown JMP opcode %u\n", opcode);
		return EINVAL;
	}

	/*
	 * EBPF_JA should meet following requirements.
	 *
	 * 1. source == EBPF_SRC_IMM
	 * 2. dst == 0
	 * 3. src == 0
	 * 4. imm == 0
	 */
	if (opcode == EBPF_JA) {
		if (source != EBPF_SRC_IMM || inst->dst != 0 ||
				inst->src != 0 || inst->imm != 0) {
			printf("Syntax Error: JA instruction uses reserved field\n");
			return EINVAL;
		}
		return 0;
	}

	/*
	 * EBPF_EXIT should meet following requirements.
	 *
	 * 1. source == EBPF_SRC_IMM
	 * 2. dst == 0
	 * 3. src == 0
	 * 4. offset == 0
	 * 5. imm == 0
	 */
	if (opcode == EBPF_EXIT) {
		if (source != EBPF_SRC_IMM || inst->dst != 0 ||
				inst->src != 0 || inst->offset != 0 ||
				inst->imm != 0) {
			printf("Syntax Error: EXIT instruction uses reserved field\n");
			return EINVAL;
		}
		return 0;
	}

	/*
	 * EBPF_CALL should meet following requirements.
	 *
	 * 1. source == EBPF_SRC_IMM
	 * 2. dst == 0
	 * 3. src == 0
	 * 4. offset == 0
	 */
	if (opcode == EBPF_CALL) {
		if (source != EBPF_SRC_IMM || inst->dst != 0 ||
				inst->src != 0 || inst->offset != 0) {
			printf("Syntax Error: CALL instruction uses reserved field\n");
			return EINVAL;
		}
		return 0;
	}

	if (source == EBPF_SRC_IMM) {
		if (inst->src != 0) {
			printf("Syntax Error: JMP instruction uses reserved field\n");
			return EINVAL;
		}
	} else /* source == EBPF_SRC_REG */ {
		if (inst->imm != 0) {
			printf("Syntax Error: JMP instruction uses reserved field\n");
			return EINVAL;
		}
	}

	return 0;
}

static int
check_ld(struct ebpf_verifier *v, struct ebpf_inst *inst)
{
	int error;

	error = check_syntax_ld(v, inst);
	if (error) {
		return error;
	}

	return 0;
}

static int
check_st(struct ebpf_verifier *v, struct ebpf_inst *inst)
{
	int error;

	error = check_syntax_st(v, inst);
	if (error) {
		return error;
	}

	return 0;
}

static int
check_alu(struct ebpf_verifier *v, struct ebpf_inst *inst)
{
	int error;

	error = check_syntax_alu(v, inst);
	if (error) {
		return error;
	}

	error = check_type_alu(v, inst);
	if (error) {
		return error;
	}

	error = simulate_alu(v, inst);
	if (error) {
		return error;
	}

	return 0;
}

static int
check_jmp(struct ebpf_verifier *v, struct ebpf_inst *inst)
{
	int error;

	error = check_syntax_jmp(v, inst);
	if (error) {
		return error;
	}

	return 0;
}

static int
do_check(struct ebpf_verifier *v)
{
	int error = 0;

	init_registers(v);

	error = stack_init(v);
	if (error) {
		return error;
	}

	error = stack_push(v, 0);
	assert(error == 0);

	while (!stack_empty(v)) {
		uint16_t idx;
		struct ebpf_inst *inst;
		struct inst_node *node;

		error = stack_pop(v, &idx);
		assert(error == 0);

		inst = v->insts + idx;
		node = v->nodes + idx;

		/*
		print_inst(inst, stderr);
		fprintf(stderr, "\n");
		*/

		error = check_syntax_common(v, inst);
		if (error) {
			goto end;
		}

		switch (EBPF_CLS(inst->opcode)) {
			case EBPF_CLS_LD:
			case EBPF_CLS_LDX:
				error = check_ld(v, inst);
				break;
			case EBPF_CLS_ST:
			case EBPF_CLS_STX:
				error = check_st(v, inst);
				break;
			case EBPF_CLS_ALU:
			case EBPF_CLS_ALU64:
				error = check_alu(v, inst);
				break;
			case EBPF_CLS_JMP:
				error = check_jmp(v, inst);
				break;
			default:
				error = EINVAL;
				break;
		}

		if (error) {
			goto end;
		}

		print_verifier_state(v, inst);

		for (uint8_t i = 0; i < node->nedges; i++) {
			stack_push(v, node->edges[i].idx);
		}

		if (!stack_empty(v)) {
			fprintf(v->out_file, ",");
		}
	}

end:
	stack_deinit(v);
	return error;
}

static int
cfg_add_edge(struct ebpf_verifier *v, struct inst_node *node,
		uint16_t idx)
{
	if (node->nedges == 2) {
		fprintf(stderr, "Reached to the limit number of the edge\n");
		return EINVAL;
	}

	if (idx >= v->ninsts) {
		fprintf(stderr, "out of range jump to index(%u)\n", idx);
		return EINVAL;
	}

	node->edges[node->nedges].idx = idx;
	node->nedges++;

	return 0;
}

static int
create_cfg(struct ebpf_verifier *v)
{
	int error;
	struct inst_node *node;
	struct ebpf_inst *inst;

	for (uint16_t i = 0; i < v->ninsts; i++) {
		inst = v->insts + i;
		node = v->nodes + i;

		switch (EBPF_CLS(inst->opcode)) {
			case EBPF_CLS_JMP:
				/* ignore exit instruction */
				if (inst->opcode == EBPF_OP_EXIT) {
					break;
				}

				/* call instruction has only one edge */
				if (inst->opcode == EBPF_OP_CALL) {
					error = cfg_add_edge(v, node, i + 1);
					break;
				}

				/* unconditional jump has only one edge */
				if (inst->opcode == EBPF_OP_JA) {
					error = cfg_add_edge(v, node, i + inst->offset + 1);
					break;
				}

				/* conditional jump has two edges */
				error = cfg_add_edge(v, node, i + inst->offset + 1);
				if (error) {
					break;
				}

				error = cfg_add_edge(v, node, i + 1);
				if (error) {
					break;
				}

				break;
			case EBPF_CLS_LD:
				/* LDDW instruction takes two instructions */
				if (inst->opcode == EBPF_OP_LDDW) {
					error = cfg_add_edge(v, node, i + 2);
					i++;
					break;
				}

				/* fall through */
			default:
				error = cfg_add_edge(v, node, i + 1);
				break;
		}

		if (error) {
			return error;
		}
	}

	return 0;
}

static int
do_dfs(struct ebpf_verifier *v)
{
	int error = 0;
	struct inst_node *node;
	struct inst_edge *edge;

	node = v->nodes;
	node->discovered = true;

	/*
	 * Return earlier if the first instruction doesn't have
	 * any edge. This may be a case which the program
	 * consists of single EXIT or first instruction is EXIT
	 * and rest of the program is unreachable. The latter case
	 * will be rejected by next reachability check, so just
	 * return 0 in here.
	 */
	if (node->nedges == 0) {
		return 0;
	}

	/*
	 * Use minimal inline stack. We don't have to do overflow
	 * check, because the depth will never become greater than
	 * instruction number.
	 */
	struct inst_edge **stack_cur, **stack_start, **stack_end;
	stack_start = calloc(sizeof(*stack_start), v->ninsts);
	if (stack_start == NULL) {
		return ENOMEM;
	}

	stack_cur = stack_start;
	stack_end = stack_start + v->ninsts;

	for (uint8_t i = 0; i < node->nedges; i++) {
		*stack_cur++ = node->edges + i;
	}

	while (stack_cur != stack_start) {
		edge = *--stack_cur;
		if (edge->passed == true) {
			error = EINVAL;
			break;
		}

		edge->passed = true;

		node = v->nodes + edge->idx;
		node->discovered = true;
		for (uint8_t i = 0; i < node->nedges; i++) {
			*stack_cur++ = node->edges + i;
		}
	}

	free(stack_start);
	return error;
}

static bool
unreachable_inst_exists(struct ebpf_verifier *v)
{
	for (uint16_t i = 0; i < v->ninsts; i++) {
		if (v->nodes[i].discovered == false) {
			return true;
		}
	}

	return false;
}

static void
generate_dot(struct ebpf_verifier *v)
{
	fprintf(v->dot_file, "digraph cfg {");
	for (uint16_t i = 0; i < v->ninsts; i++) {
		fprintf(v->dot_file, "%u[label=\"", i);
		print_inst(v->insts + i, v->dot_file);
		fprintf(v->dot_file, "\"];");
		for (uint8_t j = 0; j < v->nodes[i].nedges; j++) {
			fprintf(v->dot_file, "%u->%u;", i, v->nodes[i].edges[j].idx);
		}
	}
	fprintf(v->dot_file, "}");
}

int
ebpf_validate(struct ebpf_inst *insts, uint16_t ninsts)
{
	int error;
	struct ebpf_verifier v;

	v.out_file = fopen("verifier_states.json", "w");
	v.dot_file = fopen("cfg.dot", "w");

	v.ninsts = ninsts;
	v.insts = insts;

	v.nodes = calloc(ninsts, sizeof(v.nodes[0]));
	if (v.nodes == NULL) {
		return ENOMEM;
	}

	error = create_cfg(&v);
	if (error) {
		goto err0;
	}

	generate_dot(&v);

	error = do_dfs(&v);
	if (error) {
		goto err0;
	}

	if (unreachable_inst_exists(&v)) {
		printf("unreachable instruction exists\n");
		goto err0;
	}

	fprintf(v.out_file, "{\"states\":[\n");
	error = do_check(&v);
	if (error) {
		goto err0;
	}
	fprintf(v.out_file, "]}\n");

err0:
	free(v.nodes); 
	return error;
}

struct ebpf_inst test_prog1[] = {
	{ EBPF_OP_MOV64_IMM, 1, 0, 0, 1 },
	{ EBPF_OP_ADD64_IMM, 1, 0, 0, 2 },
	{ EBPF_OP_MOV64_IMM, 2, 0, 0, 3 },
	{ EBPF_OP_SUB64_REG, 1, 2, 0, 0 },
	{ EBPF_OP_ADD64_IMM, 1, 0, 0, -1 },
	{ EBPF_OP_MUL64_IMM, 1, 0, 0, 3 },
	{ EBPF_OP_MOV64_REG, 0, 1, 0, 0 },
	{ EBPF_OP_EXIT, 0, 0, 0, 0 }
};

struct ebpf_inst test_prog2[] = {
	{ EBPF_OP_MOV64_REG, 1, 0, 0, 0 },
	{ EBPF_OP_MOV64_REG, 2, 0, 0, 0 },
	{ EBPF_OP_MOV64_REG, 3, 0, 0, 0 },
	{ EBPF_OP_JEQ_IMM, 1, 0, -3, 0 },
	{ EBPF_OP_EXIT, 0, 0, 0, 0 }
};

struct ebpf_inst test_prog3[] = {
	{ EBPF_OP_MOV64_REG, 6, 1, 0, 0 },
	{ EBPF_OP_STXDW, 10, 6, -8, 0 },
	{ EBPF_OP_LDXDW, 0, 10, -8, 0 },
	{ EBPF_OP_LDXW, 0, 0, -3, 0 },
	{ EBPF_OP_EXIT, 0, 0, 0, 0 },
};

struct ebpf_inst test_prog4[] = {
	{ EBPF_OP_MOV64_IMM, 0, 0, 0, 1 },
	{ EBPF_OP_MOV64_REG, 1, 0, 0, 0 },
	{ EBPF_OP_MOV64_IMM, 0, 0, 0, 0 },
	{ EBPF_OP_AND64_IMM, 1, 0, 0, 0xff },
	{ EBPF_OP_JSET_IMM, 1, 0, 3, 0xf0 },
	{ EBPF_OP_JLT_IMM, 1, 0, 1, 0x10 },
	{ EBPF_OP_LDXB, 8, 9, 0, 0 },
	{ EBPF_OP_EXIT, 0, 0, 0, 0 },
	{ EBPF_OP_JSET_IMM, 1, 0, 1, 0x10 },
	{ EBPF_OP_EXIT, 0, 0, 0, 0 },
	{ EBPF_OP_JGE_IMM, 1, 0, 1, 0x10 },
	{ EBPF_OP_LDXB, 8, 9, 0, 0 },
	{ EBPF_OP_EXIT, 0, 0, 0, 0 }
};

int
main(void)
{
	int error;

	error = ebpf_validate(test_prog1, 8);
	printf("test1: %s\n", strerror(error));

	error = ebpf_validate(test_prog2, 5);
	printf("test2: %s\n", strerror(error));

	error = ebpf_validate(test_prog3, 5);
	printf("test3: %s\n", strerror(error));

	error = ebpf_validate(test_prog4, 13);
	printf("test4: %s\n", strerror(error));

	return 0;
}
