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

#include "ebpf_freebsd_user.h"
#include <sys/ebpf.h>

void *
ebpf_malloc(size_t size)
{
    return malloc(size);
}

void *
ebpf_realloc(void *ptr, size_t size)
{
    return realloc(ptr, size);
}

void *
ebpf_calloc(size_t number, size_t size)
{
    return calloc(number, size);
}

void *
ebpf_exalloc(size_t size)
{
    void *ret = NULL;

    ret = mmap(NULL, size, PROT_READ | PROT_WRITE | PROT_EXEC,
               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (ret == MAP_FAILED) {
        fprintf(stderr, "mmap in ebpf_exalloc failed\n");
        return NULL;
    }

    return ret;
}

void
ebpf_exfree(void *mem, size_t size)
{
    munmap(mem, size);
}

void
ebpf_free(void *mem)
{
    free(mem);
}

int
ebpf_error(const char *fmt, ...)
{
    int ret;
    va_list ap;

    va_start(ap, fmt);
    ret = vfprintf(stderr, fmt, ap);
    va_end(ap);

    return ret;
}

void
ebpf_assert(bool expr)
{
    assert(expr);
}
