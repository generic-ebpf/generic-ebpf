/*-
 * SPDX-License-Identifier: Apache License 2.0
 *
 * Copyright 2017-2018 Yutaro Hayakawa
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

/*-
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (c) 2018 Yutaro Hayakawa
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#include <dev/ebpf/ebpf_platform.h>
#include <sys/ebpf.h>
#include <sys/ebpf_vm.h>
#include <dev/ebpf/ebpf_prog.h>
#include <dev/ebpf/ebpf_map.h>

void *
ebpf_malloc(size_t size)
{
	return kmalloc(size, GFP_NOWAIT);
}

void *
ebpf_calloc(size_t number, size_t size)
{
	void *ret = kmalloc(number * size, GFP_NOWAIT);
	if (ret == NULL) {
		return NULL;
	}

	memset(ret, 0, number * size);

	return ret;
}

void *
ebpf_exalloc(size_t size)
{
	return __vmalloc(size, GFP_NOWAIT, PAGE_KERNEL_EXEC);
}

void
ebpf_exfree(void *mem, size_t size)
{
	vfree(mem);
}

void
ebpf_free(void *mem)
{
	kfree(mem);
}

int
ebpf_error(const char *fmt, ...)
{
	int ret;
	va_list ap;

	va_start(ap, fmt);
	ret = vprintk(fmt, ap);
	va_end(ap);

	return ret;
}

void
ebpf_assert(bool expr)
{
	BUG_ON(!(expr));
}

uint16_t
ebpf_ncpus(void)
{
	return nr_cpu_ids;
}

uint16_t
ebpf_curcpu(void)
{
  return smp_processor_id();
}

long
ebpf_getpagesize(void)
{
	return PAGE_SIZE;
}

void
ebpf_rw_init(ebpf_rwlock_t *rw, char *name)
{
	init_rwsem(rw);
}

void
ebpf_rw_rlock(ebpf_rwlock_t *rw)
{
	down_read(rw);
}

void
ebpf_rw_runlock(ebpf_rwlock_t *rw)
{
	up_read(rw);
}

void
ebpf_rw_wlock(ebpf_rwlock_t *rw)
{
	down_write(rw);
}

void
ebpf_rw_wunlock(ebpf_rwlock_t *rw)
{
	up_write(rw);
}

void
ebpf_rw_destroy(ebpf_rwlock_t *rw)
{
	return;
}

void
ebpf_epoch_enter(void)
{
  rcu_read_lock();
}

void
ebpf_epoch_exit(void)
{
  rcu_read_unlock();
}

void
ebpf_epoch_call(ebpf_epoch_context_t *ctx,
    void (*callback)(ebpf_epoch_context_t *))
{
  call_rcu(ctx, callback);
}

void
ebpf_epoch_wait(void)
{
  synchronize_rcu();
}

void
ebpf_mtx_init(ebpf_mtx_t *mutex, const char *name)
{
  raw_spin_lock_init(mutex);
}

void
ebpf_mtx_lock(ebpf_mtx_t *mutex)
{
  raw_spin_lock(mutex);
}

void
ebpf_mtx_unlock(ebpf_mtx_t *mutex)
{
  raw_spin_unlock(mutex);
}

void
ebpf_mtx_destroy(ebpf_mtx_t *mutex)
{ 
  return;
}

uint32_t
ebpf_jenkins_hash(const void *buf, size_t len, uint32_t hash)
{
  return jhash(buf, len, hash);
}

void
ebpf_init_map_types(void)
{
	for (uint16_t i = 0; i < __EBPF_MAP_TYPE_MAX; i++) {
		ebpf_register_map_type(i, &bad_map_ops);
	}

	ebpf_register_map_type(EBPF_MAP_TYPE_ARRAY, &array_map_ops);
	ebpf_register_map_type(EBPF_MAP_TYPE_PERCPU_ARRAY,
			       &percpu_array_map_ops);
	ebpf_register_map_type(EBPF_MAP_TYPE_HASHTABLE, &hashtable_map_ops);
	ebpf_register_map_type(EBPF_MAP_TYPE_PERCPU_HASHTABLE,
			       &percpu_hashtable_map_ops);
}

static int
ebpf_init(void)
{
	ebpf_init_map_types();
	printk("ebpf loaded\n");
	return 0;
}

static void
ebpf_fini(void)
{
	printk("ebpf unloaded\n");
}

EXPORT_SYMBOL(ebpf_create);
EXPORT_SYMBOL(ebpf_destroy);
EXPORT_SYMBOL(ebpf_register);
EXPORT_SYMBOL(ebpf_load);
EXPORT_SYMBOL(ebpf_load_elf);
EXPORT_SYMBOL(ebpf_exec);
EXPORT_SYMBOL(ebpf_exec_jit);
EXPORT_SYMBOL(ebpf_compile);
EXPORT_SYMBOL(ebpf_malloc);
EXPORT_SYMBOL(ebpf_calloc);
EXPORT_SYMBOL(ebpf_free);
EXPORT_SYMBOL(ebpf_exalloc);
EXPORT_SYMBOL(ebpf_exfree);
EXPORT_SYMBOL(ebpf_error);
EXPORT_SYMBOL(ebpf_assert);
EXPORT_SYMBOL(ebpf_ncpus);
EXPORT_SYMBOL(ebpf_rw_init);
EXPORT_SYMBOL(ebpf_rw_rlock);
EXPORT_SYMBOL(ebpf_rw_runlock);
EXPORT_SYMBOL(ebpf_rw_wlock);
EXPORT_SYMBOL(ebpf_rw_wunlock);
EXPORT_SYMBOL(ebpf_rw_destroy);
EXPORT_SYMBOL(ebpf_epoch_enter);
EXPORT_SYMBOL(ebpf_epoch_exit);
EXPORT_SYMBOL(ebpf_epoch_call);
EXPORT_SYMBOL(ebpf_epoch_wait);
EXPORT_SYMBOL(ebpf_mtx_init);
EXPORT_SYMBOL(ebpf_mtx_lock);
EXPORT_SYMBOL(ebpf_mtx_unlock);
EXPORT_SYMBOL(ebpf_mtx_destroy);
EXPORT_SYMBOL(ebpf_jenkins_hash);
EXPORT_SYMBOL(ebpf_prog_init);
EXPORT_SYMBOL(ebpf_prog_deinit_default);
EXPORT_SYMBOL(ebpf_prog_deinit);
EXPORT_SYMBOL(ebpf_map_delete_elem);
EXPORT_SYMBOL(ebpf_map_lookup_elem);
EXPORT_SYMBOL(ebpf_map_update_elem);
EXPORT_SYMBOL(ebpf_map_delete_elem_from_user);
EXPORT_SYMBOL(ebpf_map_lookup_elem_from_user);
EXPORT_SYMBOL(ebpf_map_update_elem_from_user);
EXPORT_SYMBOL(ebpf_map_get_next_key_from_user);
EXPORT_SYMBOL(ebpf_map_init);
EXPORT_SYMBOL(ebpf_map_deinit_default);
EXPORT_SYMBOL(ebpf_map_deinit);

module_init(ebpf_init);
module_exit(ebpf_fini);
MODULE_AUTHOR("Yutaro Hayakawa");
MODULE_DESCRIPTION("Generic eBPF Module");
MODULE_LICENSE("Dual BSD/GPL");
