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

#include <dev/ebpf/ebpf_kern.h>
#include <dev/ebpf/ebpf_obj.h>
#include <sys/ebpf.h>

/*
 * Platform dependent function implementations
 */
void *
ebpf_malloc(size_t size)
{
    return malloc(size, M_DEVBUF, M_WAITOK);
}

void *
ebpf_calloc(size_t number, size_t size)
{
    return malloc(number * size, M_DEVBUF, M_WAITOK | M_ZERO);
}

void *
ebpf_exalloc(size_t size)
{
    return malloc(size, M_DEVBUF, M_WAITOK);
}

void
ebpf_exfree(void *mem, size_t size)
{
    free(mem, M_DEVBUF);
}

void
ebpf_free(void *mem)
{
    free(mem, M_DEVBUF);
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

int
ebpf_copyin(const void *uaddr, void *kaddr, size_t len)
{
  return copyin(uaddr, kaddr, len);
}

int
ebpf_copyout(const void *kaddr, void *uaddr, size_t len)
{
  return copyout(kaddr, uaddr, len);
}

static struct fileops ebpf_objf_ops;

static int
ebpf_objfile_close(struct file *fp, struct thread *td)
{
  struct ebpf_obj *obj = fp->f_data;

  if (!fp->f_count) {
    ebpf_obj_delete(obj);
  }

  return 0;
}

int
ebpf_obj_get_desc(ebpf_thread_t *td, struct ebpf_obj *data)
{
  int error;
  int fd;
  struct file *fp;

  error = falloc(td, &fp, &fd, 0);
  if (error) {
    return error;
  }

  /*
   * File operation definition for ebpf object file.
   * It simply check reference count on file close
   * and execute destractor of the ebpf object if
   * the reference count was 0. It doesn't allow to
   * perform any file operations except close(2)
   */
  memcpy(&ebpf_objf_ops, &badfileops, sizeof(struct fileops));
  ebpf_objf_ops.fo_close = ebpf_objfile_close;

  /*
   * finit reserves two reference count for us, so release one
   * since we don't need it.
   */
  finit(fp, FREAD | FWRITE, DTYPE_NONE, data, &ebpf_objf_ops);
  fdrop(fp, td);

  return fd;
}

int
ebpf_fget(ebpf_thread_t *td, int fd, ebpf_file_t **f)
{
  cap_rights_t cap;
  return fget(td, fd, cap_rights_init(&cap, CAP_IOCTL), f);
}

/*
 * Character device operations
 */
static int
ebpf_open(struct cdev *dev, int oflags, int devtype, struct thread *td)
{
  int error = 0;
  printf("test ebpf_open\n");
  return error;
}

static int
ebpf_close(struct cdev *dev, int fflag, int devtype, struct thread *td)
{
  printf("test ebpf_close\n");
  return 0;
}

static int
freebsd_ebpf_ioctl(struct cdev *dev, u_long cmd, caddr_t data,
    int ffla, struct thread *td)
{
  int error;
  error = ebpf_ioctl(cmd, data, td);
  return error;
}

static struct cdev *ebpf_dev;
static struct cdevsw ebpf_cdevsw = {
  .d_version = D_VERSION,
  .d_name = "ebpf",
  .d_open = ebpf_open,
  .d_ioctl = freebsd_ebpf_ioctl,
  .d_close = ebpf_close
};

/*
 * Kernel module operations
 */
void ebpf_fini(void);
int ebpf_init(void);

void
ebpf_fini(void)
{
  if (ebpf_dev) {
    destroy_dev(ebpf_dev);
  }
  printf("ebpf unloaded\n");
}

int
ebpf_init(void)
{
  ebpf_dev = make_dev_credf(MAKEDEV_ETERNAL_KLD,
      &ebpf_cdevsw, 0, NULL, UID_ROOT, GID_WHEEL, 0600,
            "ebpf");
  if (!ebpf_dev) {
    goto fail;
  }

  printf("ebpf loaded\n");
  return 0;
fail:
  ebpf_fini();
  return EINVAL;
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
