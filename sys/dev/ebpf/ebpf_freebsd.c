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

#include <sys/ebpf.h>
#include <dev/ebpf/ebpf_platform.h>
#include <dev/ebpf/ebpf_map.h>

MALLOC_DECLARE(M_EBPFBUF);
MALLOC_DEFINE(M_EBPFBUF, "ebpf-buffers", "Buffers for ebpf and its subsystems");

/*
 * Platform dependent function implementations
 */
void *
ebpf_malloc(size_t size)
{
	return malloc(size, M_EBPFBUF, M_NOWAIT);
}

void *
ebpf_calloc(size_t number, size_t size)
{
	return malloc(number * size, M_EBPFBUF, M_NOWAIT | M_ZERO);
}

void *
ebpf_realloc(void *ptr, size_t size)
{
	return realloc(ptr, size, M_EBPFBUF, M_NOWAIT);
}

void *
ebpf_exalloc(size_t size)
{
	return malloc(size, M_EBPFBUF, M_NOWAIT | M_EXEC);
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

long
ebpf_getpagesize(void)
{
	return PAGE_SIZE;
}

void
ebpf_rw_init(ebpf_rwlock_t *rw, char *name)
{
	rw_init(rw, name);
}

void
ebpf_rw_rlock(ebpf_rwlock_t *rw)
{
	rw_rlock(rw);
}

void
ebpf_rw_runlock(ebpf_rwlock_t *rw)
{
	rw_runlock(rw);
}

void
ebpf_rw_wlock(ebpf_rwlock_t *rw)
{
	rw_wlock(rw);
}

void
ebpf_rw_wunlock(ebpf_rwlock_t *rw)
{
	rw_wunlock(rw);
}

void
ebpf_rw_destroy(ebpf_rwlock_t *rw)
{
	rw_destroy(rw);
}

static epoch_t ebpf_epoch;

void
ebpf_epoch_enter(void)
{
	epoch_enter(ebpf_epoch);
}

void
ebpf_epoch_exit(void)
{
	epoch_exit(ebpf_epoch);
}

void
ebpf_epoch_call(ebpf_epoch_context_t *ctx,
		void (*callback)(ebpf_epoch_context_t *))
{
	epoch_call(ebpf_epoch, ctx, callback);
}

void
ebpf_epoch_wait(void)
{
	epoch_wait(ebpf_epoch);
}

void
ebpf_mtx_init(ebpf_mtx_t *mutex, const char *name)
{
	mtx_init(mutex, name, NULL, MTX_SPIN);
}

void
ebpf_mtx_lock(ebpf_mtx_t *mutex)
{
	mtx_lock_spin(mutex);
}

void
ebpf_mtx_unlock(ebpf_mtx_t *mutex)
{
	mtx_unlock_spin(mutex);
}

void
ebpf_mtx_destroy(ebpf_mtx_t *mutex)
{
	mtx_destroy(mutex);
}

uint32_t
ebpf_jenkins_hash(const void *buf, size_t len, uint32_t hash)
{
	return jenkins_hash(buf, len, hash);
}

/*
 * Kernel module operations
 */
static void ebpf_fini(void);
static int ebpf_init(void);
static void ebpf_init_map_types(void);

static void
ebpf_fini(void)
{
	printf("ebpf unloaded\n");
}

static void
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
	ebpf_epoch = epoch_alloc(0);
	ebpf_init_map_types();
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
