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

#ifndef _EBPF_LINUX_H_
#define _EBPF_LINUX_H_

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/elf.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
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

#endif /* _EBPF_LINUX_H_ */
