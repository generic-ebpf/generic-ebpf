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
#include <sys/ebpf_map.h>
#include <sys/ebpf_prog.h>
#include <dev/ebpf/ebpf_prog_test.h>

#include <sys/ebpf.h>
#include <sys/ebpf_vm.h>
#include <sys/ebpf_dev.h>

static struct ebpf_obj *
fd2eo(int fd, ebpf_thread *td)
{
	int error;
	ebpf_file *f;
	struct ebpf_obj *eo;

	if (fd < 0 || td == NULL)
		return NULL;

	error = ebpf_fget(td, fd, &f);
	if (error != 0)
		return NULL;

	eo = ebpf_file_get_data(f);
	ebpf_obj_acquire(eo);

	ebpf_fdrop(f, td);

	return eo;
}

static struct ebpf_prog *
fd2ep(int fd, ebpf_thread *td)
{
	struct ebpf_obj *eo = fd2eo(fd, td);
	return EO2EP(eo);
}

static struct ebpf_map *
fd2em(int fd, ebpf_thread *td)
{
	struct ebpf_obj *eo = fd2eo(fd, td);
	return EO2EM(eo);
}

/*
 * XXX: This function should not be in here. We should move
 * this function to ebpf module side and make generic
 * preprocessor.
 */
static int
ebpf_prog_preprocess(struct ebpf_prog *ep, ebpf_thread *td)
{
	int error;
	struct ebpf_inst *prog = ep->prog, *cur;
	uint16_t num_insts = ep->prog_len / sizeof(struct ebpf_inst);
	struct ebpf_map *em;

	for (uint32_t i = 0; i < num_insts; i++) {
		cur = prog + i;

		if (cur->opcode != EBPF_OP_LDDW)
			continue;

		if (i == num_insts - 1 || cur[1].opcode != 0 ||
		    cur[1].dst != 0 || cur[1].src != 0 || cur[1].offset != 0)
			return EINVAL;

		if (cur->src == 0)
			continue;

		/*
		 * Currently, only assume pseudo map descriptor
		 */
		if (cur->src != EBPF_PSEUDO_MAP_DESC)
			return EINVAL;

		em = fd2em(cur->imm, td);
		if (em == NULL)
			return EINVAL;

		cur[0].imm = (uint32_t)em;
		cur[1].imm = ((uint64_t)em) >> 32;

		/* Allow duplicate */
		error = ebpf_prog_attach_map(ep, em);

		ebpf_obj_release((struct ebpf_obj *)em);

		if (error != 0 && error != EEXIST)
			return error;

		i++;
	}

	return 0;
}

static int
ebpf_ioc_load_prog(union ebpf_req *req, ebpf_thread *td)
{
	int error, fd;
	ebpf_file *f;
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
	if (error != 0)
		goto err0;

	struct ebpf_prog_attr attr = {
		.type = req->prog_type,
		.prog = insts,
		.prog_len = req->prog_len
	};

	error = ebpf_prog_create(&ep, &attr);
	if (error != 0)
		goto err0;

	ebpf_free(insts);

	error = ebpf_prog_preprocess(ep, td);
	if (error != 0)
		goto err1;

	error = ebpf_fopen(td, &f, &fd, (struct ebpf_obj *)ep);
	if (error != 0)
		goto err1;

	error = ebpf_copyout(&fd, req->prog_fdp, sizeof(int));
	if (error != 0)
		goto err2;

	return 0;

err2:
	ebpf_fdrop(f, td);
err1:
	ebpf_prog_destroy(ep);
	return error;
err0:
	ebpf_free(insts);
	return error;
}

static int
ebpf_ioc_map_create(union ebpf_req *req, ebpf_thread *td)
{
	int error, fd;
	ebpf_file *f;
	struct ebpf_map *em;

	if (req == NULL || req->map_fdp == NULL || td == NULL)
		return EINVAL;

	struct ebpf_map_attr attr = {
		.type = req->map_type,
		.key_size = req->key_size,
		.value_size = req->value_size,
		.max_entries = req->max_entries,
		.flags = req->map_flags
	};

	error = ebpf_map_create(&em, &attr);
	if (error != 0)
		return error;

	error = ebpf_fopen(td, &f, &fd, (struct ebpf_obj *)em);
	if (error != 0)
		goto err0;

	error = ebpf_copyout(&fd, req->map_fdp, sizeof(int));
	if (error != 0)
		goto err1;

	return 0;

err1:
	ebpf_fdrop(f, td);
err0:
	ebpf_map_destroy(em);
	return error;
}

static int
ebpf_ioc_map_lookup_elem(union ebpf_req *req, ebpf_thread *td)
{
	int error = 0;
	void *k, *v;
	uint32_t nvalues;
	struct ebpf_map *em;

	if (req == NULL || td == NULL || (void *)req->key == NULL ||
			(void *)req->value == NULL)
		return EINVAL;

	em = fd2em(req->map_fd, td);
	if (em == NULL)
		return EINVAL;

	k = ebpf_malloc(em->key_size);
	if (k == NULL) {
		error = ENOMEM;
		goto err0;
	}

	nvalues = em->percpu ? ebpf_ncpus() : 1;
	v = ebpf_calloc(nvalues, em->value_size);
	if (v == NULL) {
		error = ENOMEM;
		goto err1;
	}

	error = ebpf_copyin((void *)req->key, k, em->key_size);
	if (error != 0)
		goto err2;

	error = ebpf_map_lookup_elem_from_user(em, k, v);
	if (error != 0)
		goto err2;

	error = ebpf_copyout(v, (void *)req->value,
			em->value_size * nvalues);
	if (error != 0)
		goto err2;

err2:
	ebpf_free(v);
err1:
	ebpf_free(k);
err0:
	ebpf_obj_release((struct ebpf_obj *)em);
	return error;
}

static int
ebpf_ioc_map_update_elem(union ebpf_req *req, ebpf_thread *td)
{
	int error = 0;
	void *k, *v;
	struct ebpf_map *em;

	if (req == NULL || td == NULL || (void *)req->key == NULL ||
			(void *)req->value == NULL)
		return EINVAL;

	em = fd2em(req->map_fd, td);
	if (em == NULL)
		return EINVAL;

	k = ebpf_malloc(em->key_size);
	if (k == NULL) {
		error = ENOMEM;
		goto err0;
	}

	v = ebpf_malloc(em->value_size);
	if (v == NULL) {
		error = ENOMEM;
		goto err1;
	}

	error = ebpf_copyin((void *)req->key, k, em->key_size);
	if (error != 0)
		goto err2;

	error = ebpf_copyin((void *)req->value, v, em->value_size);
	if (error != 0)
		goto err2;

	error = ebpf_map_update_elem_from_user(em, k, v, req->flags);
	if (error != 0)
		goto err2;

err2:
	ebpf_free(v);
err1:
	ebpf_free(k);
err0:
	ebpf_obj_release((struct ebpf_obj *)em);
	return error;
}

static int
ebpf_ioc_map_delete_elem(union ebpf_req *req, ebpf_thread *td)
{
	int error;
	void *k;
	struct ebpf_map *em;

	if (req == NULL || td == NULL || (void *)req->key == NULL)
		return EINVAL;

	em = fd2em(req->map_fd, td);
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
	if (error != 0)
		goto err1;

err1:
	ebpf_free(k);
err0:
	ebpf_obj_release((struct ebpf_obj *)em);
	return error;
}

static int
ebpf_ioc_map_get_next_key(union ebpf_req *req, ebpf_thread *td)
{
	int error = 0;
	void *k = NULL, *nk;
	struct ebpf_map *em;

	/*
	 * key == NULL is valid, because it means "give me a first key"
	 */
	if (req == NULL || td == NULL ||
			(void *)req->next_key == NULL)
		return EINVAL;

	em = fd2em(req->map_fd, td);
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
	if (error != 0)
		goto err2;

err2:
	ebpf_free(nk);
err1:
	if (k)
		ebpf_free(k);
err0:
	ebpf_obj_release((struct ebpf_obj *)em);
	return error;
}

static int
ebpf_ioc_run_test(union ebpf_req *req, ebpf_thread *td)
{
	int error;
	void *ctx;
	uint64_t result;
	struct ebpf_prog *ep;

	ep = fd2ep(req->prog_fd, td);
	if (ep == NULL)
		return EINVAL;

	ctx = ebpf_calloc(req->ctx_len, 1);
	if (ctx == NULL) {
		error = ENOMEM;
		goto err0;
	}

	error = ebpf_copyin(req->ctx, ctx, req->ctx_len);
	if (error != 0)
		goto err1;

	error = ebpf_run_test(ep->prog, ep->prog_len,
			ctx, req->ctx_len, req->jit, &result);
	if (error != 0)
		goto err1;

	error = ebpf_copyout(&result, req->test_result, sizeof(result));
	if (error != 0)
		goto err1;

err1:
	ebpf_free(ctx);
err0:
	ebpf_obj_release((struct ebpf_obj *)ep);
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
