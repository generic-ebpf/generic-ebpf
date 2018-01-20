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

#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

#include <sys/ebpf_dev.h>

#include "ebpf_iface.h"
#include "ebpf_dev_iface.h"

static int
ebpf_dev_load_prog(EBPFIface *self, uint16_t prog_type,
    void *prog, uint32_t prog_len)
{
  struct ebpf_dev_iface *iface = (struct ebpf_dev_iface *)self;
  int fd, error;

  union ebpf_req req;
  req.prog_fdp = &fd; 
  req.prog_type = prog_type;
  req.prog_len = prog_len;
  req.prog = prog;

  error = ioctl(iface->ebpf_fd, EBPFIOC_LOAD_PROG, &req);
  if (error) {
    return error;
  }

  return fd;
}

static int
ebpf_dev_map_create(EBPFIface *self, uint16_t type, uint32_t key_size,
    uint32_t value_size, uint32_t max_entries, uint32_t map_flags)
{
  struct ebpf_dev_iface *iface = (struct ebpf_dev_iface *)self;
  int fd, error;

  union ebpf_req req;
  req.map_fdp = &fd;
  req.map_type = type;
  req.key_size = key_size;
  req.value_size = value_size;
  req.max_entries = max_entries;
  req.map_flags = map_flags;

  error = ioctl(iface->ebpf_fd, EBPFIOC_MAP_CREATE, &req);
  if (error) {
    return error;
  }

  return fd;
}

static int
ebpf_dev_map_update_elem(EBPFIface *self, int map_desc,
    void *key, void *value, uint64_t flags)
{
  struct ebpf_dev_iface *iface = (struct ebpf_dev_iface *)self;
  union ebpf_req req;
  req.map_fd = map_desc;
  req.key = key;
  req.value = value;
  req.flags = flags;

  return ioctl(iface->ebpf_fd, EBPFIOC_MAP_UPDATE_ELEM, &req);
}

static int
ebpf_dev_map_lookup_elem(EBPFIface *self, int map_desc,
    void *key, void *value, uint64_t flags)
{
  struct ebpf_dev_iface *iface = (struct ebpf_dev_iface *)self;
  union ebpf_req req;
  req.map_fd = map_desc;
  req.key = key;
  req.value = value;
  req.flags = flags;

  return ioctl(iface->ebpf_fd, EBPFIOC_MAP_LOOKUP_ELEM, &req);
}

static int
ebpf_dev_map_delete_elem(EBPFIface *self, int map_desc, void *key)
{
  struct ebpf_dev_iface *iface = (struct ebpf_dev_iface *)self;
  union ebpf_req req;
  req.map_fd = map_desc;
  req.key = key;

  return ioctl(iface->ebpf_fd, EBPFIOC_MAP_LOOKUP_ELEM, &req);
}

static int
ebpf_dev_map_get_next_key(EBPFIface *self, int map_desc,
    void *key, void *next_key)
{
  struct ebpf_dev_iface *iface = (struct ebpf_dev_iface *)self;
  union ebpf_req req;
  req.map_fd = map_desc;
  req.key = key;
  req.next_key = next_key;

  return ioctl(iface->ebpf_fd, EBPFIOC_MAP_GET_NEXT_KEY, &req);
}

static void
ebpf_dev_close_prog_desc(EBPFIface *self, int prog_desc)
{
  close(prog_desc);
}

static void
ebpf_dev_close_map_desc(EBPFIface *self, int map_desc)
{
  close(map_desc);
}

EBPFDevIface*
ebpf_dev_iface_create(void)
{
  struct ebpf_dev_iface *iface = malloc(sizeof(struct ebpf_dev_iface));
  if (!iface) {
    return NULL;
  }

  iface->ebpf_fd = open("/dev/ebpf", O_RDWR);
  if (iface->ebpf_fd < 0) {
    free(iface);
    return NULL;
  }

  iface->base.load_prog = ebpf_dev_load_prog;
  iface->base.map_create = ebpf_dev_map_create;
  iface->base.map_update_elem = ebpf_dev_map_update_elem;
  iface->base.map_lookup_elem = ebpf_dev_map_lookup_elem;
  iface->base.map_delete_elem = ebpf_dev_map_delete_elem;
  iface->base.map_get_next_key = ebpf_dev_map_get_next_key;
  iface->base.close_prog_desc = ebpf_dev_close_prog_desc;
  iface->base.close_map_desc = ebpf_dev_close_map_desc;

  return iface;
}

void
ebpf_dev_iface_destroy(EBPFDevIface *iface)
{
  close(iface->ebpf_fd);
  free(iface);
}
