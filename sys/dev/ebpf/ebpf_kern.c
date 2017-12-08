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

  if (req->prog_type >= __EBPF_PROG_TYPE_MAX) {
    return -EINVAL;
  }

  struct ebpf_inst *prog =
    ebpf_calloc(sizeof(struct ebpf_inst), req->prog_len);
  if (!prog) {
    return -ENOMEM;
  }

  error = ebpf_copyin(req->prog, prog, req->prog_len);
  if (error) {
    ebpf_free(prog);
    return error;
  }

  struct ebpf_obj_prog *prog_obj =
    (struct ebpf_obj_prog *)ebpf_obj_new(EBPF_OBJ_TYPE_PROG);
  if (!prog_obj) {
    ebpf_free(prog);
    return -ENOMEM;
  }

  error = ebpf_obj_get_desc(td, (struct ebpf_obj *)prog_obj);
  if (error < 0) {
    ebpf_free(prog);
    ebpf_free(prog_obj);
    return error;
  }

  prog_obj->prog_type = req->prog_type;
  prog_obj->prog_len = req->prog_len;
  prog_obj->prog = prog;

  error = ebpf_copyout(&error, req->prog_fd, sizeof(int));
  if (error) {
    ebpf_free(prog);
    ebpf_free(prog_obj);
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
