/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2018, Matthew Macy <mmacy@freebsd.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
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
#include <dev/ebpf/ebpf_prog_test.h>
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
	mutex_init(mutex);
}

void
ebpf_mtx_lock(ebpf_mtx_t *mutex)
{
	mutex_lock(mutex);
}

void
ebpf_mtx_unlock(ebpf_mtx_t *mutex)
{
	mutex_unlock(mutex);
}

void
ebpf_mtx_destroy(ebpf_mtx_t *mutex)
{
	mtx_destroy(mutex);
}

void
ebpf_spinmtx_init(ebpf_spinmtx_t *mutex, const char *name)
{
  raw_spin_lock_init(mutex);
}

void
ebpf_spinmtx_lock(ebpf_spinmtx_t *mutex)
{
  raw_spin_lock(mutex);
}

void
ebpf_spinmtx_unlock(ebpf_spinmtx_t *mutex)
{
  raw_spin_unlock(mutex);
}

void
ebpf_spinmtx_destroy(ebpf_spinmtx_t *mutex)
{ 
  return;
}

void
ebpf_refcount_init(uint32_t *count, uint32_t value)
{
	atomic_set(count, value);
}

void
ebpf_refcount_acquire(uint32_t *count)
{
	atomic_inc(count);
}

int
ebpf_refcount_release(uint32_t *count)
{
	return atomic_sub_and_test(1, count);
}

uint32_t
ebpf_jenkins_hash(const void *buf, size_t len, uint32_t hash)
{
  return jhash(buf, len, hash);
}

static int
ebpf_init(void)
{
	ebpf_init_map_types();
	ebpf_init_prog_types();
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
EXPORT_SYMBOL(ebpf_init_prog_types);
EXPORT_SYMBOL(ebpf_init_map_types);
EXPORT_SYMBOL(ebpf_run_test);
EXPORT_SYMBOL(ebpf_get_prog_type);
EXPORT_SYMBOL(ebpf_get_map_type);

module_init(ebpf_init);
module_exit(ebpf_fini);
MODULE_AUTHOR("Yutaro Hayakawa");
MODULE_DESCRIPTION("Generic eBPF Module");
MODULE_LICENSE("Dual BSD/GPL");
