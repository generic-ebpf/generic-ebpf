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

#include <dev/ebpf_dev/ebpf_dev_platform.h>
#include <dev/ebpf/ebpf_prog.h>
#include <dev/ebpf/ebpf_map.h>
#include <dev/ebpf_dev/ebpf_obj.h>
#include <sys/ebpf.h>
#include <sys/ebpf_dev.h>

static int
ebpf_objfile_release(struct inode *inode, struct file *filp)
{
	struct ebpf_obj *obj = filp->private_data;

	if (!atomic_read(&inode->i_count)) {
		ebpf_obj_delete(obj, current);
	}

	return 0;
}

static const struct file_operations ebpf_objf_ops = {.release =
							 ebpf_objfile_release};

bool
is_ebpf_objfile(ebpf_file_t *fp)
{
	if (!fp) {
		return false;
	}
	return fp->f_op == &ebpf_objf_ops;
}

int
ebpf_fopen(ebpf_thread_t *td, ebpf_file_t **fp, int *fd, struct ebpf_obj *data)
{
	*fd = anon_inode_getfd("ebpf-map", &ebpf_objf_ops, data, O_RDWR);

	*fp = fget(*fd);
	if (!fp) {
		return EBUSY;
	}

	fput(*fp);

	return 0;
}

int
ebpf_fget(ebpf_thread_t *td, int fd, ebpf_file_t **f)
{
	*f = fget(fd);
	if (!f) {
		return EBUSY;
	}
	return 0;
}

int
ebpf_fdrop(ebpf_file_t *f, ebpf_thread_t *td)
{
	fput(f);
	return 0;
}

int
ebpf_copyin(const void *uaddr, void *kaddr, size_t len)
{
	return copy_from_user(kaddr, uaddr, len);
}

int
ebpf_copyout(const void *kaddr, void *uaddr, size_t len)
{
	return copy_to_user(uaddr, kaddr, len);
}

ebpf_thread_t *
ebpf_curthread(void)
{
	return current;
}

/*
 * Character device operations
 */
int
ebpf_open(struct inode *inode, struct file *filp)
{
	return 0;
}

int
ebpf_close(struct inode *inode, struct file *filp)
{
	return 0;
}

long
linux_ebpf_ioctl(struct file *filp, unsigned int cmd, unsigned long data)
{
	int error;
	union ebpf_req req;

	error = copy_from_user(&req, (void *)data, sizeof(union ebpf_req));
	if (error) {
		return -error;
	}

	error = ebpf_ioctl(cmd, &req, current);
	if (error) {
		return -error;
	}

	if ((void *)data) {
		error =
		    copy_to_user((void *)data, &req, sizeof(union ebpf_req));
	}

	return -error;
}

static struct file_operations ebpf_dev_fops = {.owner = THIS_MODULE,
					       .open = ebpf_open,
					       .unlocked_ioctl =
						   linux_ebpf_ioctl,
					       .release = ebpf_close};

struct miscdevice ebpf_dev_cdev = {MISC_DYNAMIC_MINOR, "ebpf", &ebpf_dev_fops};

/*
 * Kernel module operations
 */
static __exit void
ebpf_dev_fini(void)
{
	misc_deregister(&ebpf_dev_cdev);
	printk("ebpf-dev unloaded\n");
}

static __init int
ebpf_dev_init(void)
{
	misc_register(&ebpf_dev_cdev);
	printk(KERN_INFO "ebpf-dev loaded\n");
	return 0;
}

EXPORT_SYMBOL(ebpf_fopen);
EXPORT_SYMBOL(ebpf_fget);
EXPORT_SYMBOL(ebpf_fdrop);
EXPORT_SYMBOL(ebpf_copyin);
EXPORT_SYMBOL(ebpf_copyout);
EXPORT_SYMBOL(ebpf_curthread);
EXPORT_SYMBOL(ebpf_objfile_get_container);
EXPORT_SYMBOL(ebpf_obj_delete);

module_init(ebpf_dev_init);
module_exit(ebpf_dev_fini);
MODULE_LICENSE("Dual BSD/GPL");
