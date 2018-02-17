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

#include <dev/ebpf/ebpf_platform.h>
#include <sys/ebpf.h>

MALLOC_DEFINE(M_EBPFBUF, "ebpf-buffers", "Buffers for ebpf and its subsystems");

/*
 * Platform dependent function implementations
 */
void *
ebpf_malloc(size_t size)
{
    return malloc(size, M_EBPFBUF, M_WAITOK);
}

void *
ebpf_calloc(size_t number, size_t size)
{
    return malloc(number * size, M_EBPFBUF, M_WAITOK | M_ZERO);
}

void *
ebpf_realloc(void *ptr, size_t size)
{
    return realloc(ptr, size, M_EBPFBUF, M_WAITOK);
}

void *
ebpf_exalloc(size_t size)
{
    return malloc(size, M_EBPFBUF, M_WAITOK);
}

void
ebpf_exfree(void *mem, size_t size)
{
    free(mem, M_EBPFBUF);
}

void
ebpf_free(void *mem)
{
    free(mem, M_EBPFBUF);
}

int
ebpf_error(const char *fmt, ...)
{
    int ret;
    __va_list ap;

    va_start(ap, fmt);
    ret = vprintf(fmt, ap);
    va_end(ap);

    return ret;
}

void
ebpf_assert(bool expr)
{
    KASSERT(expr, "");
}

uint16_t
ebpf_ncpus(void)
{
  return mp_maxid + 1;
}

uint16_t
ebpf_curcpu(void)
{
  return curcpu;
}

/*
 * Kernel module operations
 */
void ebpf_fini(void);
int ebpf_init(void);

void
ebpf_fini(void)
{
    printf("ebpf unloaded\n");
}

int
ebpf_init(void)
{
    printf("ebpf loaded\n");
    return 0;
}

static int
ebpf_loader(__unused struct module *module, int event, __unused void *arg)
{
    int error = 0;

    switch (event) {
    case MOD_LOAD:
        error = ebpf_init();
        break;
    case MOD_UNLOAD:
        ebpf_fini();
        break;
    default:
        error = EOPNOTSUPP;
        break;
    }

    return (error);
}

DEV_MODULE(ebpf, ebpf_loader, NULL);
MODULE_VERSION(ebpf, 1);
