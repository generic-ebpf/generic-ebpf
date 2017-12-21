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
#include <sys/ebpf_dev.h>

static int
ebpf_load_prog(union ebpf_req *req, ebpf_thread_t *td)
{
  int error;
  struct ebpf_obj_prog *prog;
  struct ebpf_inst *tmp;

  if (!req || !td) {
    return EINVAL;
  }

  /*
   * Assume the program is already pass the user space
   * verification, believe it and allocate requested amount
   * of memory without any checks
   */
  tmp = ebpf_calloc(req->prog_len, 1);
  if (!tmp) {
    return ENOMEM;
  }

  /*
   * Redundant copy, but it is needed for better generarization
   * of ebpf_obj_new
   */
  error = ebpf_copyin(req->prog, tmp, req->prog_len);
  if (error) {
    ebpf_free(tmp);
    return error;
  }

  req->prog = tmp;

  error = ebpf_obj_new((struct ebpf_obj **)&prog, EBPF_OBJ_TYPE_PROG, req);
  if (error) {
    ebpf_free(tmp);
    return error;
  }

  ebpf_free(tmp);

  error = ebpf_obj_get_fdesc(td, (struct ebpf_obj *)prog);
  if (error < 0) {
    ebpf_free(prog);
    return error;
  }

  error = ebpf_copyout(&error, req->prog_fdp, sizeof(int));
  if (error) {
    ebpf_free(prog);
    return error;
  }

  return 0;
}

static int
ebpf_map_create(union ebpf_req *req, ebpf_thread_t *td)
{
  int error;
  struct ebpf_obj_map *map;

  if (!req || !td) {
    return EINVAL;
  }

  error = ebpf_obj_new((struct ebpf_obj **)&map, EBPF_OBJ_TYPE_MAP, req);
  if (error) {
    return error;
  }

  error = ebpf_obj_get_fdesc(td, (struct ebpf_obj *)map);
  if (error < 0) {
    ebpf_obj_delete((struct ebpf_obj *)map);
    return error;
  }

  error = ebpf_copyout(&error, req->map_fdp, sizeof(int));
  if (error) {
    ebpf_obj_delete((struct ebpf_obj *)map);
    return error;
  }

  return 0;
}

static int
ebpf_ioc_map_lookup_elem(union ebpf_req *req, ebpf_thread_t *td)
{
  int error;
  ebpf_file_t *f;

  if (!req || !td || !(void *)req->key
      || !(void *)req->value) {
    return EINVAL;
  }

  error = ebpf_fget(td, req->map_fd, &f);
  if (error) {
    return error;
  }

  void *k, *v;
  struct ebpf_obj_map *map = EBPF_OBJ_MAP(f);

  k = ebpf_malloc(map->key_size);
  if (!k) {
    error = ENOMEM;
    goto err0;
  }

  error = ebpf_copyin((void *)req->key, k, map->key_size);
  if (error) {
    goto err1;
  }

  v = ebpf_map_lookup_elem(map, k, req->flags);
  if (!v) {
    error = ENOENT;
    goto err1;
  }

  error = ebpf_copyout(v, (void *)req->value, map->value_size);

err1:
  ebpf_free(k);
err0:
  ebpf_fdrop(f, td);
  return error;
}

static int
ebpf_ioc_map_update_elem(union ebpf_req *req, ebpf_thread_t *td)
{
  int error;
  ebpf_file_t *f;

  if (!req || !td || !(void *)req->key
      || !(void *)req->value) {
    return EINVAL;
  }

  error = ebpf_fget(td, req->map_fd, &f);
  if (error) {
    return error;
  }

  void *k, *v;
  struct ebpf_obj_map *map = EBPF_OBJ_MAP(f);

  k = ebpf_malloc(map->key_size);
  if (!k) {
    error = ENOMEM;
    goto err0;
  }

  error = ebpf_copyin((void *)req->key, k, map->key_size);
  if (error) {
    goto err1;
  }

  v = ebpf_malloc(map->value_size);
  if (!v) {
    error = ENOMEM;
    goto err1;
  }

  error = ebpf_copyin((void *)req->value, v, map->value_size);
  if (error) {
    goto err2;
  }

  error = ebpf_map_update_elem(map, k, v, req->flags);
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

static int
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
  struct ebpf_obj_map *map = EBPF_OBJ_MAP(f);

  k = ebpf_malloc(map->key_size);
  if (!k) {
    error = ENOMEM;
    goto err0;
  }

  error = ebpf_copyin((void *)req->key, k, map->key_size);
  if (error) {
    goto err1;
  }

  error = ebpf_map_delete_elem(map, k);

err1:
  ebpf_free(k);
err0:
  ebpf_fdrop(f, td);
  return error;
}

static int
ebpf_ioc_map_get_next_key(union ebpf_req *req, ebpf_thread_t *td)
{
  int error;
  ebpf_file_t *f;

  if (!req || !td ||
      !(void *)req->key || !(void *)req->value) {
    return EINVAL;
  }

  error = ebpf_fget(td, req->map_fd, &f);
  if (error) {
    return error;
  }

  void *k, *nk;
  struct ebpf_obj_map *map = EBPF_OBJ_MAP(f);

  k = ebpf_malloc(map->key_size);
  if (!k) {
    error = ENOMEM;
    goto err0;
  }

  error = ebpf_copyin((void *)req->key, k, map->key_size);
  if (error) {
    goto err1;
  }

  nk = ebpf_malloc(map->key_size);
  if (!nk) {
    error = ENOMEM;
    goto err1;
  }

  error = ebpf_map_get_next_key(map, k, nk);
  if (error) {
    goto err2;
  }

  error = ebpf_copyout(nk, (void *)req->next_key, map->key_size);

err2:
  ebpf_free(nk);
err1:
  ebpf_free(k);
err0:
  ebpf_fdrop(f, td);
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
    default:
      error = EINVAL;
      break;
  }

  return error;
}
