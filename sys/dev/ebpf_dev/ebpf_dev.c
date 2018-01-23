/*
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

#include "ebpf_dev_platform.h"
#include <dev/ebpf/ebpf_map.h>

#include <sys/ebpf.h>
#include <sys/ebpf_vm.h>
#include <sys/ebpf_dev.h>

void ebpf_dev_prog_deinit(struct ebpf_prog *self, void *arg);
void ebpf_dev_map_deinit(struct ebpf_map *self, void *arg);
int ebpf_prog_mapfd_to_addr(struct ebpf_obj_prog *prog_obj, ebpf_thread_t *td);
int ebpf_load_prog(union ebpf_req *req, ebpf_thread_t *td);
int ebpf_map_create(union ebpf_req *req, ebpf_thread_t *td);
int ebpf_ioc_map_lookup_elem(union ebpf_req *req, ebpf_thread_t *td);
int ebpf_ioc_map_update_elem(union ebpf_req *req, ebpf_thread_t *td);
int ebpf_ioc_map_delete_elem(union ebpf_req *req, ebpf_thread_t *td);
int ebpf_ioc_map_get_next_key(union ebpf_req *req, ebpf_thread_t *td);
void test_vm_attach_func(struct ebpf_vm *vm);
int ebpf_ioc_run_test(union ebpf_req *req, ebpf_thread_t *td);

void
ebpf_dev_prog_deinit(struct ebpf_prog *self, void *arg)
{
    struct ebpf_obj_prog *prog = (struct ebpf_obj_prog *)self;
    ebpf_thread_t *td = (ebpf_thread_t *)arg;
    ebpf_fdrop(prog->obj.f, td);
}

void
ebpf_dev_map_deinit(struct ebpf_map *self, void *arg)
{
    struct ebpf_obj_map *map = (struct ebpf_obj_map *)self;
    ebpf_thread_t *td = (ebpf_thread_t *)arg;
    ebpf_fdrop(map->obj.f, td);
}

int
ebpf_prog_mapfd_to_addr(struct ebpf_obj_prog *prog_obj, ebpf_thread_t *td)
{
    int error;
    struct ebpf_inst *prog = prog_obj->prog.prog, *cur;
    uint16_t num_insts = prog_obj->prog.prog_len / sizeof(struct ebpf_inst);
    ebpf_file_t *f;
    struct ebpf_obj_map *map;

    for (uint32_t i = 0; i < num_insts; i++) {
        cur = prog + i;

        if (cur->opcode != EBPF_OP_LDDW) {
            continue;
        }

        if (i == num_insts - 1 || cur[1].opcode != 0 ||
            cur[1].dst != 0 || cur[1].src != 0 ||
            cur[1].offset != 0) {
            error = EINVAL;
            goto err0;
        }

        // Normal lddw
        if (cur->src == 0) {
            continue;
        }
        
        if (cur->src != EBPF_PSEUDO_MAP_DESC) {
            error = EINVAL;
            goto err0;
        }

        error = ebpf_fget(td, cur->imm, &f);
        if (error) {
            goto err0;
        }

        map = ebpf_objfile_get_container(f);
        if (!map) {
            error = EINVAL;
            goto err1;
        }

        if (prog_obj->nattached_maps == EBPF_PROG_MAX_ATTACHED_MAPS) {
            error = E2BIG;
            goto err1;
        }

        cur[0].imm = (uint32_t)map;
        cur[1].imm = ((uint64_t)map) >> 32;

        for (int j = 0; j < EBPF_PROG_MAX_ATTACHED_MAPS; j++) {
            if (prog_obj->attached_maps[j]) {
                if (prog_obj->attached_maps[j] == map) {
                    ebpf_fdrop(f, td);
                    break;
                }
            } else {
                prog_obj->attached_maps[j] = map;
                prog_obj->nattached_maps++;
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
        if (prog_obj->attached_maps[i]) {
            ebpf_fdrop(f, td);
            prog_obj->attached_maps[i] = NULL;
        } else {
            break;
        }
    }

    return error;
}

int
ebpf_load_prog(union ebpf_req *req, ebpf_thread_t *td)
{
    int error;
    struct ebpf_obj_prog *prog;
    struct ebpf_inst *insts;

    if (!req || !req->prog_fdp || req->prog_type >= __EBPF_PROG_TYPE_MAX ||
        !req->prog || !req->prog_len || !td) {
        return EINVAL;
    }

    insts = ebpf_malloc(req->prog_len);
    if (!insts) {
        return ENOMEM;
    }

    error =
        ebpf_copyin(req->prog, insts, req->prog_len);
    if (error) {
        ebpf_free(insts);
        return error;
    }

    prog = ebpf_calloc(sizeof(struct ebpf_obj_prog), 1);
    if (!prog) {
        ebpf_free(insts);
        return ENOMEM;
    }

    error = ebpf_prog_init(&prog->prog, req->prog_type, insts, req->prog_len);
    if (error) {
        ebpf_free(insts);
        ebpf_free(prog);
        return error;
    }

    error = ebpf_prog_mapfd_to_addr(prog, td);
    if (error) {
        ebpf_prog_deinit(&prog->prog, td);
        ebpf_free(insts);
        ebpf_free(prog);
        return error;
    }

    int fd;
    ebpf_file_t *f;

    error = ebpf_fopen(td, &f, &fd, &prog->obj);
    if (error) {
        ebpf_prog_deinit(&prog->prog, td);
        ebpf_free(insts);
        ebpf_free(prog);
        return error;
    }

    prog->obj.f = f;
    prog->obj.type = EBPF_OBJ_TYPE_PROG;

    // set destructor after object bounded to file
    prog->prog.deinit = ebpf_dev_prog_deinit;

    error = ebpf_copyout(&fd, req->prog_fdp, sizeof(int));
    if (error) {
        ebpf_prog_deinit(&prog->prog, td);
        ebpf_free(insts);
        return error;
    }

    ebpf_free(insts);

    return 0;
}

int
ebpf_map_create(union ebpf_req *req, ebpf_thread_t *td)
{
    int error;
    struct ebpf_obj_map *map;

    if (!req || !req->map_fdp || !td) {
        return EINVAL;
    }

    map = ebpf_malloc(sizeof(struct ebpf_obj_map));
    if (!map) {
        return ENOMEM;
    }

    error = ebpf_map_init(&map->map, req->map_type, req->key_size,
                          req->value_size, req->max_entries, req->map_flags);
    if (error) {
        ebpf_free(map);
        return error;
    }

    int fd;
    ebpf_file_t *f;

    error = ebpf_fopen(td, &f, &fd, &map->obj);
    if (error) {
        ebpf_map_deinit(&map->map, td);
        ebpf_free(map);
        return error;
    }

    map->obj.f = f;
    map->obj.type = EBPF_OBJ_TYPE_MAP;

    // set destructor after object bounded to file
    map->map.deinit = ebpf_dev_map_deinit;

    error = ebpf_copyout(&fd, req->map_fdp, sizeof(int));
    if (error) {
        ebpf_map_deinit(&map->map, td);
        return error;
    }

    return 0;
}

int
ebpf_ioc_map_lookup_elem(union ebpf_req *req, ebpf_thread_t *td)
{
    int error;
    ebpf_file_t *f;

    if (!req || !td || !(void *)req->key || !(void *)req->value) {
        return EINVAL;
    }

    error = ebpf_fget(td, req->map_fd, &f);
    if (error) {
        return error;
    }

    void *k, *v;
    struct ebpf_obj_map *map = ebpf_objfile_get_container(f);
    if (!map) {
        return EINVAL;
    }

    k = ebpf_malloc(map->map.key_size);
    if (!k) {
        error = ENOMEM;
        goto err0;
    }

    error = ebpf_copyin((void *)req->key, k, map->map.key_size);
    if (error) {
        goto err1;
    }

    v = ebpf_map_lookup_elem(&map->map, k, req->flags);
    if (!v) {
        error = ENOENT;
        goto err1;
    }

    error = ebpf_copyout(v, (void *)req->value, map->map.value_size);

err1:
    ebpf_free(k);
err0:
    ebpf_fdrop(f, td);
    return error;
}

int
ebpf_ioc_map_update_elem(union ebpf_req *req, ebpf_thread_t *td)
{
    int error;
    ebpf_file_t *f;

    if (!req || !td || !(void *)req->key || !(void *)req->value) {
        return EINVAL;
    }

    error = ebpf_fget(td, req->map_fd, &f);
    if (error) {
        return error;
    }

    void *k, *v;
    struct ebpf_obj_map *map = ebpf_objfile_get_container(f);
    if (!map) {
        return EINVAL;
    }

    k = ebpf_malloc(map->map.key_size);
    if (!k) {
        error = ENOMEM;
        goto err0;
    }

    error = ebpf_copyin((void *)req->key, k, map->map.key_size);
    if (error) {
        goto err1;
    }

    v = ebpf_malloc(map->map.value_size);
    if (!v) {
        error = ENOMEM;
        goto err1;
    }

    error = ebpf_copyin((void *)req->value, v, map->map.value_size);
    if (error) {
        goto err2;
    }

    error = ebpf_map_update_elem(&map->map, k, v, req->flags);
    if (error) {
        goto err2;
    }

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

int
ebpf_ioc_map_delete_elem(union ebpf_req *req, ebpf_thread_t *td)
{
    int error;
    ebpf_file_t *f;

    if (!req || !td || !(void *)req->key) {
        return EINVAL;
    }

    error = ebpf_fget(td, req->map_fd, &f);
    if (error) {
        return error;
    }

    void *k;
    struct ebpf_obj_map *map = ebpf_objfile_get_container(f);
    if (!map) {
        return EINVAL;
    }

    k = ebpf_malloc(map->map.key_size);
    if (!k) {
        error = ENOMEM;
        goto err0;
    }

    error = ebpf_copyin((void *)req->key, k, map->map.key_size);
    if (error) {
        goto err1;
    }

    error = ebpf_map_delete_elem(&map->map, k);

err1:
    ebpf_free(k);
err0:
    ebpf_fdrop(f, td);
    return error;
}

int
ebpf_ioc_map_get_next_key(union ebpf_req *req, ebpf_thread_t *td)
{
    int error;
    ebpf_file_t *f;

    if (!req || !td || !(void *)req->key || !(void *)req->value) {
        return EINVAL;
    }

    error = ebpf_fget(td, req->map_fd, &f);
    if (error) {
        return error;
    }

    void *k, *nk;
    struct ebpf_obj_map *map = ebpf_objfile_get_container(f);
    if (!map) {
        return EINVAL;
    }

    k = ebpf_malloc(map->map.key_size);
    if (!k) {
        error = ENOMEM;
        goto err0;
    }

    error = ebpf_copyin((void *)req->key, k, map->map.key_size);
    if (error) {
        goto err1;
    }

    nk = ebpf_malloc(map->map.key_size);
    if (!nk) {
        error = ENOMEM;
        goto err1;
    }

    error = ebpf_map_get_next_key(&map->map, k, nk);
    if (error) {
        goto err2;
    }

    error = ebpf_copyout(nk, (void *)req->next_key, map->map.key_size);

err2:
    ebpf_free(nk);
err1:
    ebpf_free(k);
err0:
    ebpf_fdrop(f, td);
    return error;
}

void
test_vm_attach_func(struct ebpf_vm *vm) {
    ebpf_register(vm, 0, "ebpf_map_update_elem", ebpf_map_update_elem);
    ebpf_register(vm, 1, "ebpf_map_lookup_elem", ebpf_map_lookup_elem);
    ebpf_register(vm, 2, "ebpf_map_delete_elem", ebpf_map_delete_elem);
}
    
int
ebpf_ioc_run_test(union ebpf_req *req, ebpf_thread_t *td)
{
    int error;
    struct ebpf_vm *vm;

    vm = ebpf_create();
    if (vm == NULL) {
        return ENOMEM;
    }
    test_vm_attach_func(vm);

    ebpf_file_t *f;
    error = ebpf_fget(td, req->prog_fd, &f);
    if (error) {
        goto err0;
    }

    struct ebpf_obj_prog *prog_obj = ebpf_objfile_get_container(f);
    if (!prog_obj) {
        error =  EINVAL;
        goto err1;
    }

    error = ebpf_load(vm, prog_obj->prog.prog, prog_obj->prog.prog_len);
    if (error < 0) {
        error =  EINVAL;
        goto err1;
    }

    void *ctx = ebpf_calloc(req->ctx_len, 1);
    if (ctx == NULL) {
        error = ENOMEM;
        goto err1;
    }

    error = ebpf_copyin(req->ctx, ctx, req->ctx_len);
    if (error) {
        goto err2;
    }

    uint64_t result;
    if (req->jit) {
        ebpf_jit_fn fn = ebpf_compile(vm);
        if (!fn) {
            error = EINVAL;
            goto err2;
        }
        result = fn(ctx, req->ctx_len);
    } else {
        result = ebpf_exec(vm, ctx, req->ctx_len);
    }

    error = ebpf_copyout(&result, req->test_result, sizeof(uint64_t));

err2:
    ebpf_free(ctx);
err1:
    ebpf_fdrop(f, td);
err0:
    ebpf_destroy(vm);
    return error;
}

int
ebpf_ioctl(uint32_t cmd, void *data, ebpf_thread_t *td)
{
    int error;
    union ebpf_req *req = (union ebpf_req *)data;

    if (!data || !td) {
        return EINVAL;
    }

    switch (cmd) {
    case EBPFIOC_LOAD_PROG:
        error = ebpf_load_prog(req, td);
        break;
    case EBPFIOC_MAP_CREATE:
        error = ebpf_map_create(req, td);
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
    default:
        error = EINVAL;
        break;
    }

    return error;
}
