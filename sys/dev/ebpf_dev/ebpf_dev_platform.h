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

#pragma once

#include <dev/ebpf/ebpf_obj.h>

#ifdef __FreeBSD__
#include "ebpf_dev_freebsd.h"
#elif defined(linux)
#include <ebpf_dev_linux.h>
#else
#error Unsupported platform
#endif

/*
 * Prototypes of platform dependent functions.
 */
int ebpf_obj_get_fdesc(ebpf_thread_t *td, struct ebpf_obj *data);
int ebpf_fget(ebpf_thread_t *td, int fd, ebpf_file_t **f);
int ebpf_fdrop(ebpf_file_t *f, ebpf_thread_t *td);
int ebpf_copyin(const void *uaddr, void *kaddr, size_t len);
int ebpf_copyout(const void *kaddr, void *uaddr, size_t len);
int ebpf_ioctl(uint32_t cmd, void *data, ebpf_thread_t *td);
