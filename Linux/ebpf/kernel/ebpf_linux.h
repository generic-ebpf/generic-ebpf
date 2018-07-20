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

#pragma once

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/elf.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/cpumask.h>
#include <linux/rwsem.h>
#include <linux/spinlock.h>
#include <linux/jhash.h>
#include <linux/rcupdate.h>
#include <linux/rculist.h>
#include <asm/byteorder.h>

#define UINT64_MAX U64_MAX
#define UINT32_MAX U32_MAX
#define INT32_MAX S32_MAX
#define INT32_MIN S32_MIN

#define htole16(x) cpu_to_le16(x)
#define htole32(x) cpu_to_le32(x)
#define htole64(x) cpu_to_le64(x)

#define htobe16(x) cpu_to_be16(x)
#define htobe32(x) cpu_to_be32(x)
#define htobe64(x) cpu_to_be64(x)

#define ENOTSUP EOPNOTSUPP

typedef struct rw_semaphore ebpf_rwlock_t;
typedef struct rcu_head ebpf_epoch_context_t;
typedef raw_spinlock_t ebpf_mtx_t;

#define EBPF_EPOCH_LIST_ENTRY(_type) struct hlist_node
#define EBPF_EPOCH_LIST_EMPTY(_type) hlist_empty(_type)
#define EBPF_EPOCH_LIST_FIRST(_headp, _type, _name) \
  hlist_entry(hlist_first_rcu(_headp), _type, _name)
#define EBPF_EPOCH_LIST_HEAD(_name, _type) struct hlist_head
#define EBPF_EPOCH_LIST_INIT(_headp) INIT_HLIST_HEAD(_headp)
#define EBPF_EPOCH_LIST_FOREACH(_var, _head, _name) hlist_for_each_entry_rcu(_var, _head, _name)
#define EBPF_EPOCH_LIST_INSERT_HEAD(_head, _elem, _name) hlist_add_head_rcu(&_elem->_name, _head)
#define EBPF_EPOCH_LIST_REMOVE(_elem, _name) hlist_del_rcu(&_elem->_name)
#define EBPF_EPOCH_LIST_NEXT(_elem, _name) \
  hlist_entry(hlist_next_rcu(&_elem->_name), typeof(*_elem), _name)
