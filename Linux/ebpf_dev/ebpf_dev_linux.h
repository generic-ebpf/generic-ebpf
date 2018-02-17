/* 
 * Copyright (c) 2017 Yutaro Hayakawa
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
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
#include <linux/cpumask.h>
#include <asm/byteorder.h>

typedef struct task_struct ebpf_thread_t;
typedef struct file ebpf_file_t;

#include <dev/ebpf_dev/ebpf_obj.h>

#define EBPF_OBJ(filep) filep->private_data
#define EBPF_OBJ_MAP(filep) (struct ebpf_obj_map *)filep->private_data
