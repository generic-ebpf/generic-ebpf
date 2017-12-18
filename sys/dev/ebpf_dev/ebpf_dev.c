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

#include "ebpf_dev.h"
#include <dev/ebpf/ebpf_map.h>

#include <sys/ebpf.h>
#include <sys/ebpf_ioctl.h>

static int
ebpf_load_prog(union ebpf_req *req, ebpf_thread_t *td)
{
  int error;
  struct ebpf_obj_prog *prog;
  struct ebpf_inst *tmp;

  /*
   * Assume the program is already pass the user space
   * verification, believe it and allocate requested amount
   * of memory without any checks
   */
  tmp = ebpf_calloc(req->prog_len, 1);
  if (tmp == NULL) {
    return ENOMEM;
  }

  /*
   * Redundant copy, but it is needed for better generarization
   * of ebpf_obj_new
   */
  error = ebpf_copyin(req->prog, tmp, req->prog_len);
  if (error) {
    return -error;
  }

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

int
ebpf_map_create(union ebpf_req *req, ebpf_thread_t *td)
{
  int error;
  struct ebpf_obj_map *map;

  map = ebpf_calloc(sizeof(struct ebpf_obj_map), 1);
  if (map == NULL) {
    return ENOMEM;
  }

  error = ebpf_obj_new((struct ebpf_obj **)&map, EBPF_OBJ_TYPE_MAP, req);
  if (error) {
    ebpf_free(map);
    return error;
  }

  error = ebpf_obj_get_fdesc(td, (struct ebpf_obj *)map);
  if (error < 0) {
    ebpf_free(map);
    return error;
  }

  error = ebpf_copyout(&error, req->map_fdp, sizeof(int));
  if (error) {
    ebpf_free(map);
    return error;
  }

  return 0;
}

int
ebpf_ioc_map_lookup_elem(union ebpf_req *req, ebpf_thread_t *td)
{
  int error;
  ebpf_file_t *f;

  error = ebpf_fget(td, req->map_fd, &f);
  if (error) {
    return error;
  }

  error = ebpf_map_ops[req->map_type]->lookup_elem((struct ebpf_obj_map *)EBPF_OBJ(f),
      (void *)req->key, (void *)req->value, req->flags);
  if (error) {
    return error;
  }

  return 0;
}

int
ebpf_ioc_map_update_elem(union ebpf_req *req, ebpf_thread_t *td)
{
  int error;
  ebpf_file_t *f;

  error = ebpf_fget(td, req->map_fd, &f);
  if (error) {
    ebpf_error("Error in ebpf_fget\n");
    return error;
  }

  error = ebpf_map_ops[req->map_type]->update_elem((struct ebpf_obj_map *)EBPF_OBJ(f),
      (void *)req->key, (void *)req->value, req->flags);
  if (error) {
    ebpf_error("Error in update elem\n");
    return error;
  }

  return 0;
}

int
ebpf_ioc_map_delete_elem(union ebpf_req *req, ebpf_thread_t *td)
{
  int error;
  ebpf_file_t *f;

  error = ebpf_fget(td, req->map_fd, &f);
  if (error) {
    return error;
  }

  error = ebpf_map_ops[req->map_type]->delete_elem((struct ebpf_obj_map *)EBPF_OBJ(f),
      (void *)req->key);
  if (error) {
    return error;
  }

  return 0;
}

int
ebpf_ioc_map_get_next_key(union ebpf_req *req, ebpf_thread_t *td)
{
  int error;
  ebpf_file_t *f;

  error = ebpf_fget(td, req->map_fd, &f);
  if (error) {
    return error;
  }

  error = ebpf_map_ops[req->map_type]->get_next_key((struct ebpf_obj_map *)EBPF_OBJ(f),
      (void *)req->key, (void *)req->next_key);
  if (error) {
    return error;
  }

  return 0;
}

int
ebpf_ioctl(uint32_t cmd, void *data, ebpf_thread_t *td)
{
  int error;
  union ebpf_req *req = (union ebpf_req *)data;

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
