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

#include <dev/ebpf/ebpf_platform.h>
#include <dev/ebpf/ebpf_map.h>
#include <sys/ebpf.h>

/*
 * Define what kind of maps this platform can use.
 * Need to sync with enum ebpf_map_types in <platform>_types.h
 */
extern struct ebpf_map_ops array_map_ops;
extern struct ebpf_map_ops hashtable_map_ops;

const struct ebpf_map_ops *ebpf_map_ops[__EBPF_MAP_TYPE_MAX] =
    {[EBPF_MAP_TYPE_ARRAY] = &array_map_ops,
     [EBPF_MAP_TYPE_HASHTABLE] = &hashtable_map_ops};

void *
ebpf_malloc(size_t size)
{
	return malloc(size);
}

void *
ebpf_calloc(size_t number, size_t size)
{
	return calloc(number, size);
}

void *
ebpf_realloc(void *ptr, size_t size)
{
	return realloc(ptr, size);
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
