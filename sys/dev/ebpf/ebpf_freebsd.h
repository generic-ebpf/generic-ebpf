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

#pragma once

#include <sys/param.h>
#include <sys/conf.h>
#include <sys/proc.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/elf.h>
#include <sys/endian.h>
#include <sys/ioccom.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/fcntl.h>
#include <sys/refcount.h>
#include <sys/capsicum.h>
#include <sys/smp.h>
#include <sys/stddef.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/rwlock.h>
#include <sys/epoch.h>
#include <sys/refcount.h>
#include <sys/hash.h>
#include <machine/stdarg.h>

#include <ck_queue.h>

typedef struct rwlock ebpf_rwlock_t;
typedef epoch_context_t ebpf_epoch_context_t;
typedef struct mtx ebpf_mtx_t;

#define EBPF_EPOCH_LIST_ENTRY(_type) CK_LIST_ENTRY(_type)
#define EBPF_EPOCH_LIST_HEAD(_name, _type) \
	CK_LIST_HEAD(_head, _type)
#define EBPF_EPOCH_LIST_INIT(_headp) CK_LIST_INIT(_headp)
#define EBPF_EPOCH_LIST_FOREACH(_var, _head, _name) \
	CK_LIST_FOREACH(_var, _head, _name)
#define EBPF_EPOCH_LIST_INSERT_HEAD(_head, _elem, _name) \
	CK_LIST_INSERT_HEAD(_head, _elem, _name)
#define EBPF_EPOCH_LIST_REMOVE(_elem, _name) \
	CK_LIST_REMOVE(_elem, _name)
#define EBPF_EPOCH_LIST_NEXT(_elem, _name) \
	CK_LIST_NEXT(_elem, _name)
