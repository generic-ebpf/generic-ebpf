/*-
 * SPDX-License-Identifier: Apache License 2.0
 *
 * Copyright 2018 Yutaro Hayakawa
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
#include <dev/ebpf/ebpf_map.h>
#include <dev/ebpf/ebpf_prog.h>
#include <dev/ebpf/ebpf_epoch.h>
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

uint16_t
ebpf_ncpus(void)
{
	return sysconf(_SC_NPROCESSORS_ONLN);
}

uint16_t
ebpf_curcpu(void)
{
	return 0; // This makes no sense. Just for testing.
}

long
ebpf_getpagesize(void)
{
	return sysconf(_SC_PAGE_SIZE);
}

void
ebpf_rw_init(ebpf_rwlock_t *rw, char *name)
{
	int error = pthread_rwlock_init(rw, NULL);
	assert(!error);
}

void
ebpf_rw_rlock(ebpf_rwlock_t *rw)
{
	int error = pthread_rwlock_rdlock(rw);
	assert(!error);
}

void
ebpf_rw_runlock(ebpf_rwlock_t *rw)
{
	int error = pthread_rwlock_unlock(rw);
	assert(!error);
}

void
ebpf_rw_wlock(ebpf_rwlock_t *rw)
{
	int error = pthread_rwlock_wrlock(rw);
	assert(!error);
}

void
ebpf_rw_wunlock(ebpf_rwlock_t *rw)
{
	int error = pthread_rwlock_unlock(rw);
	assert(!error);
}

void
ebpf_rw_destroy(ebpf_rwlock_t *rw)
{
	int error = pthread_rwlock_destroy(rw);
	assert(!error);
}

void
ebpf_refcount_init(volatile uint32_t *count, uint32_t val)
{
	*count = val;
}

void
ebpf_refcount_acquire(volatile uint32_t *count)
{
	*count++;
}

int
ebpf_refcount_release(volatile uint32_t *count)
{
	*count--;
	if (count == 0) {
		return 1;
	}
	return 0;
}

void
ebpf_mtx_init(ebpf_mtx_t *mutex, const char *name)
{
	int error = pthread_mutex_init(mutex, NULL);
	assert(!error);
}

void
ebpf_mtx_lock(ebpf_mtx_t *mutex)
{
	int error = pthread_mutex_lock(mutex);
	assert(!error);
}

void
ebpf_mtx_unlock(ebpf_mtx_t *mutex)
{
	int error = pthread_mutex_unlock(mutex);
	assert(!error);
}

void
ebpf_mtx_destroy(ebpf_mtx_t *mutex)
{
	int error = pthread_mutex_destroy(mutex);
	assert(!error);
}

__attribute__((constructor)) void
ebpf_init(void)
{
	ebpf_epoch_init();
	ebpf_init_prog_types();
	ebpf_init_map_types();
}

__attribute__((destructor)) void
ebpf_deinit(void)
{
	ebpf_epoch_deinit();
}
