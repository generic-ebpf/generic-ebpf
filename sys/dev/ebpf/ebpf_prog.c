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

#include <dev/ebpf/ebpf_prog.h>

const struct ebpf_prog_type *ebpf_prog_types[] = {
	[EBPF_PROG_TYPE_BAD]  = &bad_prog_type,
	[EBPF_PROG_TYPE_TEST] = &test_prog_type
};

const struct ebpf_prog_type *
ebpf_get_prog_type(uint16_t type)
{
	if (type >= EBPF_PROG_TYPE_MAX) {
		return NULL;
	}

	return ebpf_prog_types[type];
}

static void
ebpf_prog_dtor(struct ebpf_obj *eo)
{
	struct ebpf_obj_prog *eop = (struct ebpf_obj_prog *)eo;

	for (uint16_t i = 0; i < eop->ndep_maps; i++) {
		ebpf_obj_release((struct ebpf_obj *)eop->dep_maps[i]);
	}

	ebpf_free(eop->prog);
}

int
ebpf_prog_create(struct ebpf_obj_prog **eopp, struct ebpf_prog_attr *attr)
{
	struct ebpf_obj_prog *eop;

	if (eopp == NULL || attr == NULL ||
			attr->type >= EBPF_PROG_TYPE_MAX ||
			attr->prog == NULL || attr->prog_len == 0)
		return EINVAL;

	eop = ebpf_malloc(sizeof(*eop));
	if (eop == NULL)
		return ENOMEM;

	eop->prog = ebpf_malloc(attr->prog_len);
	if (eop->prog == NULL) {
		ebpf_free(eop);
		return ENOMEM;
	}

	memcpy(eop->prog, attr->prog, attr->prog_len);

	ebpf_refcount_init(&eop->eo.ref, 1);
	eop->eo.type = EBPF_OBJ_TYPE_PROG;
	eop->eo.dtor = ebpf_prog_dtor;
	eop->type = attr->type;
	eop->ndep_maps = 0;
	eop->prog_len = attr->prog_len;

	memset(eop->dep_maps, 0,
			sizeof(eop->dep_maps[0]) * EOP_MAX_DEPS);

	*eopp = eop;

	return 0;
}

void
ebpf_prog_destroy(struct ebpf_obj_prog *eop)
{
	ebpf_obj_release(&eop->eo);
}

int
ebpf_prog_attach_map(struct ebpf_obj_prog *eop, struct ebpf_obj_map *eom)
{
	if (eop == NULL || eom == NULL) {
		return EINVAL;
	}

	if (eop->ndep_maps >= EOP_MAX_DEPS) {
		return EBUSY;
	}

	ebpf_obj_acquire((struct ebpf_obj *)eom);
	eop->dep_maps[eop->ndep_maps++] = eom;

	return 0;
}
