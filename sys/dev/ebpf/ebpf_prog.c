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

#include "ebpf_prog.h"

struct ebpf_prog_type *ebpf_prog_types[__EBPF_MAP_TYPE_MAX];
ebpf_mtx_t ebpf_prog_types_mutex;

int
ebpf_register_prog_type(struct ebpf_prog_type *type)
{
	int error = 0;
	uint16_t available = 0;

	ebpf_mtx_lock(&ebpf_prog_types_mutex);

	for (uint16_t i = __EBPF_BASIC_PROG_TYPE_MAX;
			i < __EBPF_PROG_TYPE_MAX; i++) {
		if (ebpf_prog_types[i] == NULL && available == 0) {
			/*
			 * Remember available slot, but don't break or assign
			 * pointer to the slot now. Because we need to iterate
			 * over all slots to check there is an entry which has
			 * same name.
			 */
			available = i;
		}

		/*
		 * Don't allow duplicated name
		 */
		if (memcmp(ebpf_prog_types[i]->name, type->name,
					EBPF_NAME_MAX) == 0) {
			error = EINVAL;
			goto end;
		}
	}

	/*
	 * No available slot
	 */
	if (available == 0) {
		error = EBUSY;
		goto end;
	}

	ebpf_refcount_init(&type->refcount, 0);
	ebpf_prog_types[available] = type;

end:
	ebpf_mtx_unlock(&ebpf_prog_types_mutex);
	return 0;
}

int
ebpf_unregister_prog_type(struct ebpf_prog_type *type)
{
	int error = 0;

	ebpf_mtx_lock(&ebpf_prog_types_mutex);

	for (uint16_t i = __EBPF_BASIC_PROG_TYPE_MAX;
			i < __EBPF_PROG_TYPE_MAX; i++) {
		if (ebpf_prog_types[i] == type) {
			if (ebpf_refcount_release(&ebpf_prog_types[i]->refcount) == 0) {
				error = EBUSY;
			} else {
				ebpf_prog_types[i] = NULL;
			}
			goto end;
		}
	}

	error = ENOENT;

end:
	ebpf_mtx_unlock(&ebpf_prog_types_mutex);
	return error;
}

int
ebpf_acquire_prog_type(uint16_t id, struct ebpf_prog_type **typep)
{
	int error = 0;

	if (id >= __EBPF_MAP_TYPE_MAX || typep == NULL) {
		return EINVAL;
	}

	ebpf_mtx_lock(&ebpf_prog_types_mutex);

	if (ebpf_prog_types[id] == NULL) {
		error = ENOENT;
		goto end;
	}

	ebpf_refcount_acquire(&ebpf_prog_types[id]->refcount);
	*typep = ebpf_prog_types[id];

end:
	ebpf_mtx_unlock(&ebpf_prog_types_mutex);
	return 0;
}

void
ebpf_release_prog_type(uint16_t id)
{
	ebpf_mtx_lock(&ebpf_prog_types_mutex);
	ebpf_refcount_release(&ebpf_prog_types[id]->refcount);
	ebpf_mtx_unlock(&ebpf_prog_types_mutex);
}

void
ebpf_init_prog_types(void)
{
	ebpf_mtx_init(&ebpf_prog_types_mutex, "ebpf_prog_types_mutex");

	for (uint16_t i = 0; i < __EBPF_PROG_TYPE_MAX; i++) {
		ebpf_prog_types[i] = NULL;
	}

	/*
	 * Register basic prog types
	 */
	ebpf_prog_types[EBPF_PROG_TYPE_BAD] = &bad_prog_type;
	ebpf_prog_types[EBPF_PROG_TYPE_TEST] = &test_prog_type;

	ebpf_refcount_init(&bad_prog_type.refcount, 0);
	ebpf_refcount_init(&test_prog_type.refcount, 0);
}

int
ebpf_deinit_prog_types(void)
{
	int error = 0;

	ebpf_mtx_lock(&ebpf_prog_types_mutex);

	for (uint16_t i = 0; i < __EBPF_MAP_TYPE_MAX; i++) {
		if (ebpf_prog_types[i] != NULL) {
			if (ebpf_prog_types[i]->refcount != 0) {
				error = EBUSY;
				goto end;
			}

			ebpf_assert(i < __EBPF_BASIC_MAP_TYPE_MAX);
			ebpf_prog_types[i] = NULL;
		}
	}

end:
	ebpf_mtx_unlock(&ebpf_prog_types_mutex);
	return error;
}

int
ebpf_prog_init(struct ebpf_prog *prog_obj, uint16_t type,
	       struct ebpf_inst *prog, uint32_t prog_len)
{
	int error;

	if (!prog_obj || type >= __EBPF_PROG_TYPE_MAX || !prog || !prog_len) {
		return EINVAL;
	}

	struct ebpf_inst *insts = ebpf_malloc(prog_len);
	if (!insts) {
		return ENOMEM;
	}
	memcpy(insts, prog, prog_len);

	struct ebpf_prog_type *typep;
	error = ebpf_acquire_prog_type(type, &typep);
	if (error) {
		return error;
	}

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
	ebpf_release_prog_type(prog_obj->type);
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
