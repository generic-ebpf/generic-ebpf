# 
# SPDX-License-Identifier: Apache License 2.0
#
# Copyright 2018 Yutaro Hayakawa
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#	http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

function sfx(name, type)
{
	if (name == "LE" || name == "BE")
		return "";
	else
		return SFX[type];
}

function opdefine(name, type, opcode)
{
	if (name == "LE")
		opcode += SRC["I"];
	if (name == "BE")
		opcode += SRC["R"];
	printf("#define\tEBPF_OP_%s%s\t\t0x%02x\n", name,
	    sfx(name, type), opcode);
}

function opheader(name, type, opcode)
{
    printf("\t\tcase EBPF_OP_%s%s:\n", name, sfx(name, type));
}

function jmpop(name, type, opcode, op, sign) {
	opheader(name, type, opcode);

	if (name == "EXIT") {
		printf("\t\t\treturn vm->state.reg[0];\n");
		return;
	}

	if (name == "JA") {
		printf("\t\t\tvm->state.pc += inst->offset;\n");
		printf("\t\t\tbreak;\n");
		return;
	}

	if (name == "CALL") {
		printf("\t\t\tvm->state.reg[0] = " \
		    "vm->ext_funcs[(uint32_t)inst->imm](");
		printf("vm->state.reg[1], vm->state.reg[2], ")
		printf("vm->state.reg[3], ");
		printf("vm->state.reg[4], vm->state.reg[5]");
		printf(");\n");
		printf("\t\t\tbreak;\n");
		return;
	}

	dst = "vm->state.reg[inst->dst]";

	if (type == "I") {
		src = "inst->imm";
	} else if (type == "R") {
		src = "vm->state.reg[inst->src]";
	} else if (type == "N") {
		# Do nothing
	} else {
		printf("Unknown type value: %s\n", type);
		exit 1;
	}

	if (sign == "u") {
		printf("\t\t\tif ((uint64_t)%s %s (uint64_t)%s) {\n", dst, op, src);
		printf("\t\t\t\tvm->state.pc += inst->offset;\n");
		printf("\t\t\t}\n");
		printf("\t\t\tbreak;\n");
	} else if (sign == "s") {
		printf("\t\t\tif ((int64_t)%s %s (int64_t)%s) {\n", dst, op, src);
		printf("\t\t\t\tvm->state.pc += inst->offset;\n");
		printf("\t\t\t}\n");
		printf("\t\t\tbreak;\n");
	} else {
		printf("Unknown sign value: %s\n", sign);
		exit 1;
	}
}

function aluop(name, type, opcode, op) {
	opheader(name, type, opcode);
	i64 = index(name, "64");

	dst = "vm->state.reg[inst->dst]";
	if (type == "I") src = "inst->imm";
	if (type == "R") src = "vm->state.reg[inst->src]"

	if (name == "MOV") {
		if (i64) {
			printf("\t\t\t%s = (uint32_t)%s;\n", dst, src);
		} else {
			printf("\t\t\t%s = (uint32_t)%s;\n", dst, src);
		}
		printf("\t\t\tbreak;\n");
	} else if (name == "NEG") {
		if (i64) {
			printf("\t\t\t%s = -%s;\n", dst, src);
		} else {
			printf("\t\t\t%s = -(uint32_t)%s;\n", dst, src);
		}
		printf("\t\t\tbreak;\n");
	} else if (name == "LE") {
		printf("\t\t\tif (%s == 16) {\n", src);
		printf("\t\t\t\t%s = htole16((uint16_t)%s);\n", dst, dst);
		printf("\t\t\t} else if (%s == 32) {\n", src);
		printf("\t\t\t\t%s = htole32((uint32_t)%s);\n", dst, dst);
		printf("\t\t\t} else if (%s == 64) {\n", src);
		printf("\t\t\t\t%s = htole64((uint64_t)%s);\n", dst, dst);
		printf("\t\t\t}\n");
		printf("\t\t\tbreak;\n");
	} else if (name == "BE") {
		printf("\t\t\tif (%s == 16) {\n", src);
		printf("\t\t\t\t%s = htobe16((uint16_t)%s);\n", dst, dst);
		printf("\t\t\t} else if (%s == 32) {\n", src);
		printf("\t\t\t\t%s = htobe32((uint32_t)%s);\n", dst, dst);
		printf("\t\t\t} else if (%s == 64) {\n", src);
		printf("\t\t\t\t%s = htobe64((uint64_t)%s);\n", dst, dst);
		printf("\t\t\t}\n");
		printf("\t\t\tbreak;\n");
	} else {
		if (i64)
			printf("\t\t\t%s = %s %s %s;\n", dst, dst, op, src);
		else
			printf("\t\t\t%s = (uint32_t)%s %s (uint32_t)%s;\n",
			       dst, dst, op, src);
		printf("\t\t\tbreak;\n");
	}
}

function ldstop(ldst, name, type, opcode, optype, op, stype, dtype) {
	opheader(name, type, opcode);

	dst = "vm->state.reg[inst->dst]";
	src = "vm->state.reg[inst->src]";
	if (type == "B") c = "uint8_t";
	if (type == "H") c = "uint16_t";
	if (type == "W") c = "uint32_t";
	if (type == "D") c = "uint64_t";
	if (ldst == "LD") {
		printf("\t\t\t%s = (uint32_t)inst->imm | ", dst);
		printf("((uint64_t)((inst + 1)->imm) << 32);\n");
		printf("\t\t\tvm->state.pc++;\n");
	} else if (match(ldst, "^LD")) {
		printf("\t\t\t%s = *(%s *)(uintptr_t)(%s + inst->offset);\n",
		    dst, c, src);
	} else if (match(ldst, "^STX")) {
		printf("\t\t\t*(%s *)(uintptr_t)(%s + inst->offset) = " \
		    "vm->state.reg[inst->src];\n", c, dst);
	} else if (match(ldst, "^ST")) {
		printf("\t\t\t*(%s *)(uintptr_t)(%s + inst->offset) = " \
		    "(%s)inst->imm;\n", c, dst, c);
	}
	printf("\t\t\tbreak;\n");
}

BEGIN {
    INDENT = 0;
	l = 0;
	if (defineonly == 0) {
		printf("#include <sys/dev/ebpf/ebpf_platform.h>\n");
		printf("#include <sys/ebpf_vm.h>\n");
		printf("#include <sys/ebpf_inst.h>\n");
		printf("uint64_t\nebpf_vm_run(struct ebpf_vm *vm, void *ctx)\n{\n");
		printf("\tvm->state.pc = 0;\n");
		printf("\tvm->state.reg[1] = (uint64_t)ctx;\n");
		printf("\tvm->state.reg[10] = (uint64_t)(vm->state.stack + sizeof(vm->state.stack))\n");
		printf("\twhile (true) {\n");
		printf("\t\tconst struct ebpf_inst *inst = vm->insts + vm->state.pc++;\n");
		printf("\t\tswitch (inst->opcode) {\n");
	} else {
		printf("#pragma once\n");
	}
	SFX["N"] = "";
}

END {
	if (defineonly) {
		opdefine("MAX", "", 255);
	} else {
		printf("\t\tdefault:\n");
		printf("\t\t\tebpf_error(\"Invalid instruction at PC %%u\\n\", " \
		    "vm->state.pc);\n" \
		    "\t\t\tebpf_assert(false);\n");
		printf("\t\t}\n");
		printf("\t}\n");
		printf("}");
	}
}

/^#/	{ }
/^CLASS/{ CLS[$2] = $3; }
/^SRC/	{ SRC[$2] = $3; SFX[$2] = $4; }
/^SIZE/	{ SIZE[$2] = $3; SFX[$2] = $4; }
/^JMP/ || /^ALU/ {
	for (S in SRC) {
		if (index($2, S))
			if (defineonly)
				opdefine($3, S, CLS[$1] + SRC[S] + $4);
			else if (match($1, "^JMP"))
				jmpop($3, S, CLS[$1] + SRC[S] + $4, $5, $6);
			else if (match($1, "^ALU"))
				aluop($3, S, CLS[$1] + SRC[S] + $4, $5);
	}
}
/^LD/ || /^ST/ {
	for (S in SIZE) {
		if (index($2, S))
			if (defineonly)
				opdefine($3, S, CLS[$1] + SIZE[S] + $4);
			else
				ldstop($1, $3, S, CLS[$1] + SIZE[S] + $4,
				    $5, $6, $7, $8);
	}
}
