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
