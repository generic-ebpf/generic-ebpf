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
	FILE *out_file;
	FILE *dot_file;
};

static void
init_registers(struct ebpf_verifier *state)
{
	for (uint8_t i = 0; i < 11; i++) {
		if (i == 1) {
			state->reg_states[i].type = PTR_TO_CTX;
		} else if (i == 10) {
			state->reg_states[i].type = PTR_TO_STACK;
		} else {
			state->reg_states[i].type = NOT_INIT;
		}

		state->reg_states[i].smax = 0;
		state->reg_states[i].smin = 0;
		state->reg_states[i].umax = 0;
		state->reg_states[i].umin = 0;
	}
}

static void
print_verifier_state(struct ebpf_verifier *state, struct ebpf_inst *inst)
{
	char *fmt;

	fprintf(state->out_file, "{\"cur_inst\": \"");
	print_inst(inst, state->out_file);
	fprintf(state->out_file, "\",\n \"registers\": [\n");
	for (uint16_t i = 0; i < 11; i++) {
		if (i == 10) {
			fmt = "{\"type\": \"%s\",\"smax\":%ld,\"smin\":%ld,\"umax\":%lu,\"umin\":%lu}\n";
		} else {
			fmt = "{\"type\": \"%s\",\"smax\":%ld,\"smin\":%ld,\"umax\":%lu,\"umin\":%lu},\n";
		}

		fprintf(state->out_file, fmt,
				reg_type_str[state->reg_states[i].type],
				state->reg_states[i].smax,
				state->reg_states[i].smin,
				state->reg_states[i].umax,
				state->reg_states[i].umin
		);
	}
	fprintf(state->out_file, "]}\n");
}

static int
check_ld(struct ebpf_verifier *state, struct ebpf_inst *inst)
{
	return 0;
}

static int
check_st(struct ebpf_verifier *state, struct ebpf_inst *inst)
{
	return 0;
}

#define ALU32_IMM2REG(_operator, _regp, _instp) do { \
	_regp->smax = regp->smax _operator _instp->imm;

static int
check_alu(struct ebpf_verifier *state, struct ebpf_inst *inst)
{
	switch (inst->opcode) {
		case EBPF_OP_ADD_IMM:
			state->reg_states[inst->dst].smax += (int64_t)inst->imm;
			state->reg_states[inst->dst].smin += (int64_t)inst->imm;
			state->reg_states[inst->dst].umax += (uint64_t)inst->imm;
			state->reg_states[inst->dst].umin += (uint64_t)inst->imm;
		case EBPF_OP_MOV64_REG:
			memcpy(state->reg_states + inst->dst,
					state->reg_states + inst->src,
					sizeof(*state->reg_states));
			break;
		case EBPF_OP_MOV64_IMM:
			state->reg_states[inst->dst].type = SCALAR_VALUE;
			state->reg_states[inst->dst].smax = (int64_t)inst->imm;
			state->reg_states[inst->dst].smin = (int64_t)inst->imm;
			state->reg_states[inst->dst].umax = (uint64_t)inst->imm;
			state->reg_states[inst->dst].umin = (uint64_t)inst->imm;
			break;
		default:
			break;
	}

	return 0;
}

static int
check_jmp(struct ebpf_verifier *state, struct ebpf_inst *inst)
{
	return 0;
}

static int
do_check(struct ebpf_verifier *state)
{
	int error = 0;
	struct ebpf_inst *inst;
	struct inst_edge *edge;
	struct inst_node *node;
	struct inst_node **stack_cur, **stack_start, **stack_end;

	init_registers(state);

	stack_start = calloc(sizeof(*stack_start), state->ninsts);
	if (stack_start == NULL) {
		return ENOMEM;
	}

	stack_cur = stack_start;
	stack_end = stack_start + state->ninsts;
	inst = state->insts;
	node = state->nodes;
	edge = NULL;

	*stack_cur++ = node;

	while (stack_cur != stack_start) {
		node = *--stack_cur;
		inst = state->insts + (node - state->nodes);

		switch (EBPF_CLS(inst->opcode)) {
			case EBPF_CLS_LD:
			case EBPF_CLS_LDX:
				error = check_ld(state, inst);
				break;
			case EBPF_CLS_ST:
			case EBPF_CLS_STX:
				error = check_st(state, inst);
				break;
			case EBPF_CLS_ALU:
			case EBPF_CLS_ALU64:
				error = check_alu(state, inst);
				break;
			case EBPF_CLS_JMP:
				error = check_jmp(state, inst);
				break;
			default:
				error = EINVAL;
				break;
		}

		if (error) {
			goto end;
		}

		print_verifier_state(state, inst);

		for (uint8_t i = 0; i < node->nedges; i++) {
			*stack_cur++ = state->nodes + (node->edges[i].idx);
		}

		if (stack_cur != stack_start) {
			fprintf(state->out_file, ",");
		}
	}

end:
	free(stack_start);
	return error;
}

static int
add_edge(struct ebpf_verifier *state, struct inst_node *node,
		uint16_t idx)
{
	if (node->nedges == 2) {
		fprintf(stderr, "Reached to the limit number of the edge\n");
		return EINVAL;
	}

	if (idx >= state->ninsts) {
		fprintf(stderr, "out of range jump to index(%u)\n", idx);
		return EINVAL;
	}

	node->edges[node->nedges].idx = idx;
	node->nedges++;

	return 0;
}

static int
create_cfg(struct ebpf_verifier *state)
{
	int error;
	struct inst_node *node;
	struct ebpf_inst *inst;

	for (uint16_t i = 0; i < state->ninsts; i++) {
		inst = state->insts + i;
		node = state->nodes + i;

		switch (EBPF_CLS(inst->opcode)) {
			case EBPF_CLS_JMP:
				/* ignore exit instruction */
				if (inst->opcode == EBPF_OP_EXIT) {
					break;
				}

				/* call instruction has only one edge */
				if (inst->opcode == EBPF_OP_CALL) {
					error = add_edge(state, node, i + 1);
					break;
				}

				/* unconditional jump has only one edge */
				if (inst->opcode == EBPF_OP_JA) {
					error = add_edge(state, node, i + inst->offset + 1);
					break;
				}

				/* conditional jump has two edges */
				error = add_edge(state, node, i + inst->offset + 1);
				if (error) {
					break;
				}

				error = add_edge(state, node, i + 1);
				if (error) {
					break;
				}

				break;
			case EBPF_CLS_LD:
				/* LDDW instruction takes two instructions */
				if (inst->opcode == EBPF_OP_LDDW) {
					error = add_edge(state, node, i + 2);
					i++;
					break;
				}

				/* fall through */
			default:
				error = add_edge(state, node, i + 1);
				break;
		}

		if (error) {
			return error;
		}
	}

	return 0;
}

static int
do_dfs(struct ebpf_verifier *state)
{
	int error = 0;
	struct inst_node *node;
	struct inst_edge *edge;
	struct inst_edge **stack_cur, **stack_start, **stack_end;

	node = state->nodes;
	stack_start = calloc(sizeof(*stack_start), state->ninsts);
	if (stack_start == NULL) {
		return ENOMEM;
	}

	stack_cur = stack_start;
	stack_end = stack_start + state->ninsts;

	for (uint8_t i = 0; i < node->nedges; i++) {
		*stack_cur++ = node->edges + i;
	}

	node->discovered = true;

	while (stack_cur != stack_start) {
		edge = *--stack_cur;
		if (edge->passed == true) {
			error = EINVAL;
			break;
		}

		edge->passed = true;

		node = state->nodes + edge->idx;
		node->discovered = true;
		for (uint8_t i = 0; i < node->nedges; i++) {
			*stack_cur++ = node->edges + i;
		}
	}

	free(stack_start);
	return error;
}

static bool
unreachable_inst_exists(struct ebpf_verifier *state)
{
	for (uint16_t i = 0; i < state->ninsts; i++) {
		if (state->nodes[i].discovered == false) {
			return true;
		}
	}

	return false;
}

static void
generate_dot(struct ebpf_verifier *state)
{
	fprintf(state->dot_file, "digraph cfg {");
	for (uint16_t i = 0; i < state->ninsts; i++) {
		fprintf(state->dot_file, "%u[label=\"", i);
		print_inst(state->insts + i, state->dot_file);
		fprintf(state->dot_file, "\"];");
		for (uint8_t j = 0; j < state->nodes[i].nedges; j++) {
			fprintf(state->dot_file, "%u->%u;", i, state->nodes[i].edges[j].idx);
		}
	}
	fprintf(state->dot_file, "}");
}

int
ebpf_validate(struct ebpf_inst *insts, uint16_t ninsts)
{
	int error;
	struct ebpf_verifier state;

	state.out_file = fopen("verifier_states.json", "w");
	state.dot_file = fopen("cfg.dot", "w");

	state.ninsts = ninsts;
	state.insts = insts;

	state.nodes = calloc(ninsts, sizeof(state.nodes[0]));
	if (state.nodes == NULL) {
		return ENOMEM;
	}

	error = create_cfg(&state);
	if (error) {
		goto err0;
	}

	generate_dot(&state);

	error = do_dfs(&state);
	if (error) {
		goto err0;
	}

	if (unreachable_inst_exists(&state)) {
		printf("unreachable instruction exists\n");
		goto err0;
	}

	fprintf(state.out_file, "{\"states\":[\n");
	error = do_check(&state);
	if (error) {
		goto err0;
	}
	fprintf(state.out_file, "]}\n");

err0:
	free(state.nodes); 
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
	{ EBPF_OP_CALL, 0, 0, 0, 1 },
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

	/*
	error = ebpf_validate(test_prog2, 5);
	printf("test2: %s\n", strerror(error));

	error = ebpf_validate(test_prog3, 5);
	printf("test3: %s\n", strerror(error));

	error = ebpf_validate(test_prog4, 13);
	printf("test4: %s\n", strerror(error));
	*/

	return 0;
}
