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

#include "ebpf_linux.h"
#include <sys/ebpf_types.h>

void *ebpf_malloc(size_t size)
{
    return kmalloc(size, GFP_KERNEL);
}

void *ebpf_calloc(size_t number, size_t size)
{
    void *ret = kmalloc(number * size, GFP_KERNEL);
    if (ret == NULL) {
        return NULL;
    }

    memset(ret, 0, number * size);

    return ret;
}

void *ebpf_exalloc(size_t size) {
    return __vmalloc(size, GFP_KERNEL, PAGE_KERNEL_EXEC);
}

void ebpf_exfree(void *mem)
{
    vfree(mem);
}

void ebpf_free(void *mem)
{
    kfree(mem);
}

int ebpf_error(const char *fmt, ...)
{
    int ret;
    va_list ap;

    va_start(ap, fmt);
    ret = vprintk(fmt, ap);
    va_end(ap);

    return ret;
}

void ebpf_assert(bool expr)
{
    BUG_ON(!(expr));
}

static int ebpf_init(void) {
    printk("ebpf loaded\n");
    return 0;
}

static void ebpf_fini(void) {
    printk("ebpf unloaded\n");
}

module_init(ebpf_init);
module_exit(ebpf_fini);
MODULE_AUTHOR("Yutaro Hayakawa");
MODULE_DESCRIPTION("Generic eBPF Module");
MODULE_LICENSE("BSD 2-Clause");
