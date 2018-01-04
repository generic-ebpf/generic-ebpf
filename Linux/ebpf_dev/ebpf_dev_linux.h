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

#pragma once

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/elf.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/miscdevice.h>
#include <linux/anon_inodes.h>
#include <linux/uaccess.h>
#include <asm/byteorder.h>

typedef struct task_struct ebpf_thread_t;
typedef struct file ebpf_file_t;

#include <dev/ebpf_dev/ebpf_obj.h>

#define EBPF_OBJ(filep) filep->private_data
#define EBPF_OBJ_MAP(filep) (struct ebpf_obj_map *)filep->private_data
