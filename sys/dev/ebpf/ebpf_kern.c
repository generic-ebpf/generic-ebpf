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

#include "ebpf_kern.h"
#include <sys/ebpf.h>

static int
ebpf_load_prog(void *data, ebpf_thread_t *td) {
  int error;
  union ebpf_req *req = (union ebpf_req *)data;
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
    return -error;
  }

  ebpf_free(tmp);

  error = ebpf_obj_get_desc(td, (struct ebpf_obj *)prog);
  if (error < 0) {
    ebpf_free(prog);
    return error;
  }

  error = ebpf_copyout(&error, req->prog_fd, sizeof(int));
  if (error) {
    ebpf_free(prog);
    return error;
  }

  return 0;
}

int
ebpf_ioctl(uint32_t cmd, void *data, ebpf_thread_t *td)
{
  int error;

  switch (cmd) {
    case EBPFIOC_LOAD_PROG:
      error = ebpf_load_prog(data, td);
      break;
    default:
      error = -EINVAL;
      break;
  }

  return error;
}
