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

#include <sys/ebpf_types.h>
#include "ebpf_freebsd.h"

void *ebpf_malloc(size_t size) {
  return malloc(size, M_DEVBUF, M_WAITOK);
}

void *ebpf_calloc(size_t number, size_t size) {
  return malloc(number * size, M_DEVBUF, M_WAITOK | M_ZERO);
}

void *ebpf_exalloc(size_t size) {
  return malloc(size, M_DEVBUF, M_WAITOK);
}

void ebpf_exfree(void *mem) {
  free(mem, M_DEVBUF);
}

void ebpf_free(void *mem) {
  free(mem, M_DEVBUF);
}

int ebpf_error(const char *fmt, ...) {
  int ret;
  __va_list ap;

  va_start(ap, fmt);
  ret = vprintf(fmt, ap);
  va_end(ap);

  return ret;
}

void ebpf_assert(bool expr) {
  KASSERT(expr, "");
}

static int
ebpf_loader(__unused struct module *module, int event, __unused void *arg) {
  int error = 0;

  switch (event) {
  case MOD_LOAD:
    printf("ebpf loaded\n");
    break;
  case MOD_UNLOAD:
    printf("ebpf unloaded\n");
    break;
  default:
    error = EOPNOTSUPP;
    break;
  }

  return (error);
}

DEV_MODULE(ebpf, ebpf_loader, NULL);
MODULE_VERSION(ebpf, 1);
