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

#include "ebpf_dev_platform.h"
#include <dev/ebpf/ebpf_map.h>
#include <dev/ebpf/ebpf_prog.h>
#include <dev/ebpf/ebpf_prog_test.h>

#include <sys/ebpf.h>
#include <sys/ebpf_vm.h>
#include <sys/ebpf_dev.h>

static void
ebpf_dev_prog_deinit(struct ebpf_prog *ep, void *arg)
{
	struct ebpf_prog *ep = (struct ebpf_prog *)ep;
	ebpf_thread *td = (ebpf_thread *)arg;
	ebpf_fdrop(ep->obj.f, td);
}

static void
ebpf_dev_map_deinit(struct ebpf_map *ep, void *arg)
{
	struct ebpf_map *map = (struct ebpf_map *)ep;
	ebpf_thread *td = (ebpf_thread *)arg;
	ebpf_fdrop(map->obj.f, td);
}

static int
ebpf_prog_mapfd_to_addr(struct ebpf_prog *ep, ebpf_thread *td)
{
	int error;
	struct ebpf_inst *prog = ep->prog, *cur;
	uint16_t num_insts = ep->prog_len / sizeof(struct ebpf_inst);
	ebpf_file *f;
	struct ebpf_map *map;

	for (uint32_t i = 0; i < num_insts; i++) {
		cur = prog + i;

		if (cur->opcode != EBPF_OP_LDDW)
			continue;

		if (i == num_insts - 1 || cur[1].opcode != 0 ||
		    cur[1].dst != 0 || cur[1].src != 0 || cur[1].offset != 0) {
			error = EINVAL;
			goto err0;
		}

		if (cur->src == 0)
			continue;

		if (cur->src != EBPF_PSEUDO_MAP_DESC) {
			error = EINVAL;
			goto err0;
		}

		error = ebpf_fget(td, cur->imm, &f);
		if (error != 0)
			goto err0;

		map = ebpf_objfile_get_container(f);
		if (map == NULL) {
			error = EINVAL;
			goto err1;
		}

		if (ep->nattached_maps == EBPF_PROG_MAX_ATTACHED_MAPS) {
			error = E2BIG;
			goto err1;
		}

		cur[0].imm = (uint32_t)map;
		cur[1].imm = ((uint64_t)map) >> 32;

		for (int j = 0; j < EBPF_PROG_MAX_ATTACHED_MAPS; j++) {
			if (ep->dep_maps[j] != NULL) {
				if (ep->dep_maps[j] == map) {
					ebpf_fdrop(f, td);
					break;
				}
			} else {
				ep->dep_maps[j] = map;
				ep->ndep_maps++;
				break;
			}
		}

		i++;
	}

	return 0;

err1:
	ebpf_fdrop(f, td);
err0:
	for (int i = 0; i < EBPF_PROG_MAX_ATTACHED_MAPS; i++) {
		if (ep->dep_maps[i] != NULL) {
			ebpf_fdrop(f, td);
			ep->dep_maps[i] = NULL;
		} else {
			break;
		}
	}

	return error;
}

static int
ebpf_ioc_load_prog(union ebpf_req *req, ebpf_thread *td)
{
	int error;
	struct ebpf_prog *ep;
	struct ebpf_inst *insts;

	if (req == NULL || req->prog_fdp == NULL ||
			req->prog_type >= EBPF_PROG_TYPE_MAX ||
	    req->prog == NULL || req->prog_len == 0 ||
	    td == NULL)
		return EINVAL;

	insts = ebpf_malloc(req->prog_len);
	if (insts == NULL)
		return ENOMEM;

	error = ebpf_copyin(req->prog, insts, req->prog_len);
	if (error != 0) {
		ebpf_free(insts);
		return error;
	}

	struct ebpf_prog_attr attr = {
		.type = req->prog_type,
		.prog = insts,
		.prog_len = req->prog_len
	};

	error = ebpf_prog_create(&ep, &attr);
	if (error != 0) {
		ebpf_free(insts);
		ebpf_free(ep);
		return error;
	}

	error = ebpf_prog_mapfd_to_addr(ep, td);
	if (error != 0) {
		ebpf_prog_destroy(ep, td);
		ebpf_free(insts);
		ebpf_free(ep);
		return error;
	}

	int fd;
	ebpf_file *f;

	error = ebpf_fopen(td, &f, &fd, ep);
	if (error != 0) {
		ebpf_prog_destroy(&ep->prog, td);
		ebpf_free(insts);
		ebpf_free(ep);
		return error;
	}

	error = ebpf_copyout(&fd, req->prog_fdp, sizeof(int));
	if (error != 0) {
		ebpf_prog_destroy(&ep->prog, td);
		ebpf_free(insts);
		return error;
	}

	ebpf_free(insts);

	return 0;
}

static int
ebpf_ioc_map_create(union ebpf_req *req, ebpf_thread *td)
{
	int error;
	struct ebpf_map *em;

	if (req == NULL || req->map_fdp == NULL || td == NULL)
		return EINVAL;

	em = ebpf_malloc(sizeof(*em));
	if (em == NULL)
		return ENOMEM;

	struct ebpf_map_attr attr = {
		.type = req->map_type,
		.key_size = req->key_size,
		.value_size = req->value_size,
		.max_entries = req->max_entries,
		.flags = req->map_flags
	};

	error = ebpf_map_create(&em, &attr);
	if (error != 0) {
		ebpf_free(em);
		return error;
	}

	int fd;
	ebpf_file *f;

	error = ebpf_fopen(td, &f, &fd, em);
	if (error != 0) {
		ebpf_map_destroy(em, td);
		ebpf_free(em);
		return error;
	}

	error = ebpf_copyout(&fd, req->map_fdp, sizeof(int));
	if (error != 0) {
		ebpf_map_destroy(em, td);
		return error;
	}

	return 0;
}

static int
ebpf_ioc_map_lookup_elem(union ebpf_req *req, ebpf_thread *td)
{
	int error;
	ebpf_file *f;

	if (req == NULL || td == NULL || (void *)req->key == NULL ||
			(void *)req->value == NULL)
		return EINVAL;

	error = ebpf_fget(td, req->map_fd, &f);
	if (error != 0)
		return error;

	void *k, *v;
	struct ebpf_map *em = ebpf_objfile_get_container(f);
	if (em == NULL)
		return EINVAL;

	k = ebpf_malloc(em->key_size);
	if (k == NULL) {
		error = ENOMEM;
		goto err0;
	}

	error = ebpf_copyin((void *)req->key, k, em->key_size);
	if (error != 0) {
		goto err1;
	}

	uint32_t ncpus = ebpf_ncpus();
	if (em->percpu) {
		v = ebpf_calloc(ncpus, em->value_size);
		if (v == NULL) {
			error = ENOMEM;
			goto err1;
		}
	} else {
		v = ebpf_calloc(1, em->value_size);
		if (v == NULL) {
			error = ENOMEM;
			goto err1;
		}
	}

	error = ebpf_map_lookup_elem_from_user(em, k, v);
	if (error != 0)
		goto err2;

	if (em->percpu)
		error = ebpf_copyout(v, (void *)req->value,
				     em->value_size * ncpus);
	else
		error =
		    ebpf_copyout(v, (void *)req->value, em->value_size);

err2:
	ebpf_free(v);
err1:
	ebpf_free(k);
err0:
	ebpf_fdrop(f, td);
	return error;
}

static int
ebpf_ioc_map_update_elem(union ebpf_req *req, ebpf_thread *td)
{
	int error;
	ebpf_file *f;

	if (req == NULL || td == NULL || (void *)req->key == NULL ||
			(void *)req->value == NULL)
		return EINVAL;

	error = ebpf_fget(td, req->map_fd, &f);
	if (error != 0)
		return error;

	void *k, *v;
	struct ebpf_map *em = ebpf_objfile_get_container(f);
	if (em == NULL)
		return EINVAL;

	k = ebpf_malloc(em->key_size);
	if (k == NULL) {
		error = ENOMEM;
		goto err0;
	}

	error = ebpf_copyin((void *)req->key, k, em->key_size);
	if (error != 0)
		goto err1;

	v = ebpf_malloc(em->value_size);
	if (v == NULL) {
		error = ENOMEM;
		goto err1;
	}

	error = ebpf_copyin((void *)req->value, v, em->value_size);
	if (error != 0)
		goto err2;

	error = ebpf_map_update_elem_from_user(em, k, v, req->flags);
	if (error != 0)
		goto err2;

	ebpf_free(k);
	ebpf_free(v);
	ebpf_fdrop(f, td);

	return 0;

err2:
	ebpf_free(v);
err1:
	ebpf_free(k);
err0:
	ebpf_fdrop(f, td);
	return error;
}

static int
ebpf_ioc_map_delete_elem(union ebpf_req *req, ebpf_thread *td)
{
	int error;
	ebpf_file *f;

	if (req == NULL || td == NULL || (void *)req->key == NULL)
		return EINVAL;

	error = ebpf_fget(td, req->map_fd, &f);
	if (error != 0)
		return error;

	void *k;
	struct ebpf_map *em = ebpf_objfile_get_container(f);
	if (em == NULL)
		return EINVAL;

	k = ebpf_malloc(em->key_size);
	if (k == NULL) {
		error = ENOMEM;
		goto err0;
	}

	error = ebpf_copyin((void *)req->key, k, em->key_size);
	if (error != 0)
		goto err1;

	error = ebpf_map_delete_elem_from_user(em, k);

err1:
	ebpf_free(k);
err0:
	ebpf_fdrop(f, td);
	return error;
}

static int
ebpf_ioc_map_get_next_key(union ebpf_req *req, ebpf_thread *td)
{
	int error;
	ebpf_file *f;

	/*
	 * key == NULL is valid, because it means "give me a first key"
	 */
	if (req == NULL || td == NULL ||
			(void *)req->next_key == NULL)
		return EINVAL;

	error = ebpf_fget(td, req->map_fd, &f);
	if (error != 0)
		return error;

	void *k = NULL, *nk;
	struct ebpf_map *em = ebpf_objfile_get_container(f);
	if (em == NULL)
		return EINVAL;

	if (req->key != NULL) {
		k = ebpf_malloc(em->key_size);
		if (k == NULL) {
			error = ENOMEM;
			goto err0;
		}

		error = ebpf_copyin((void *)req->key, k, em->key_size);
		if (error != 0)
			goto err1;
	}

	nk = ebpf_malloc(em->key_size);
	if (nk == NULL) {
		error = ENOMEM;
		goto err1;
	}

	error = ebpf_map_get_next_key_from_user(em, k, nk);
	if (error != 0)
		goto err2;

	error = ebpf_copyout(nk, (void *)req->next_key, em->key_size);

err2:
	ebpf_free(nk);
err1:
	if (k)
		ebpf_free(k);
err0:
	ebpf_fdrop(f, td);
	return error;
}

static int
ebpf_ioc_run_test(union ebpf_req *req, ebpf_thread *td)
{
	int error;

	ebpf_file *f;
	error = ebpf_fget(td, req->prog_fd, &f);
	if (error != 0)
		return error;

	struct ebpf_prog *ep = ebpf_objfile_get_container(f);
	if (ep == NULL) {
		error = EINVAL;
		goto err0;
	}

	void *ctx = ebpf_calloc(req->ctx_len, 1);
	if (ctx == NULL) {
		error = ENOMEM;
		goto err0;
	}

	error = ebpf_copyin(req->ctx, ctx, req->ctx_len);
	if (error != 0)
		goto err1;

	uint64_t result;
	error = ebpf_run_test(ep->prog, ep->prog_len,
			ctx, req->ctx_len, req->jit, &result);
	if (error != 0)
		goto err1;

	error = ebpf_copyout(&result, req->test_result, sizeof(uint64_t));

err1:
	ebpf_free(ctx);
err0:
	ebpf_fdrop(f, td);
	return error;
}

static int
ebpf_ioc_get_map_type_info(union ebpf_req *req)
{
	int error;
	if (req->mt_id >= EBPF_MAP_TYPE_MAX)
		return EINVAL;

	struct ebpf_map_type_info *info = ebpf_malloc(sizeof(*info));
	if (info == NULL)
		return ENOMEM;

	const struct ebpf_map_type *type = ebpf_get_map_type(req->mt_id);
	if (type == NULL) {
		error = ENOENT;
		goto err0;
	}

	memcpy(info->name, type->name, EBPF_NAME_MAX);

	error = ebpf_copyout(info, req->mt_info, sizeof(*info));

err0:
	ebpf_free(info);
	return error;
}

static int
ebpf_ioc_get_prog_type_info(union ebpf_req *req)
{
	int error;
	if (req->pt_id >= EBPF_PROG_TYPE_MAX)
		return EINVAL;

	struct ebpf_prog_type_info *info = ebpf_malloc(sizeof(*info));
	if (info == NULL)
		return ENOMEM;

	const struct ebpf_prog_type *type = ebpf_get_prog_type(req->pt_id);
	if (type == NULL) {
		error = ENOENT;
		goto err0;
	}

	memcpy(info->name, type->name, EBPF_NAME_MAX);

	error = ebpf_copyout(info, req->pt_info, sizeof(*info));
	if (error != 0)
		goto err0;

err0:
	ebpf_free(info);
	return error;
}

int
ebpf_ioctl(uint32_t cmd, void *data, ebpf_thread *td)
{
	int error;
	union ebpf_req *req = (union ebpf_req *)data;

	if (data == NULL || td == NULL) {
		return EINVAL;
	}

	switch (cmd) {
	case EBPFIOC_LOAD_PROG:
		error = ebpf_ioc_load_prog(req, td);
		break;
	case EBPFIOC_MAP_CREATE:
		error = ebpf_ioc_map_create(req, td);
		break;
	case EBPFIOC_MAP_LOOKUP_ELEM:
		error = ebpf_ioc_map_lookup_elem(req, td);
		break;
	case EBPFIOC_MAP_UPDATE_ELEM:
		error = ebpf_ioc_map_update_elem(req, td);
		break;
	case EBPFIOC_MAP_DELETE_ELEM:
		error = ebpf_ioc_map_delete_elem(req, td);
		break;
	case EBPFIOC_MAP_GET_NEXT_KEY:
		error = ebpf_ioc_map_get_next_key(req, td);
		break;
	case EBPFIOC_RUN_TEST:
		error = ebpf_ioc_run_test(req, td);
		break;
	case EBPFIOC_GET_MAP_TYPE_INFO:
		error = ebpf_ioc_get_map_type_info(req);
		break;
	case EBPFIOC_GET_PROG_TYPE_INFO:
		error = ebpf_ioc_get_prog_type_info(req);
		break;
	default:
		error = EINVAL;
		break;
	}

	return error;
}
