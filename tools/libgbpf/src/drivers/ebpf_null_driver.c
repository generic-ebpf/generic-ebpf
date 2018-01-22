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
#include <stdlib.h>

#include <gbpf/drivers/ebpf_null_driver.h>

static int
ebpf_null_load_prog(EBPFDriver *self, uint16_t prog_type,
    void *prog, uint32_t prog_len)
{
  return 0;
}

static int
ebpf_null_map_create(EBPFDriver *self, uint16_t type, uint32_t key_size,
    uint32_t value_size, uint32_t max_entries, uint32_t map_flags)
{
  return 0;
}

static int
ebpf_null_map_update_elem(EBPFDriver *self, int map_desc,
    void *key, void *value, uint64_t flags)
{
  return 0;
}

static int
ebpf_null_map_lookup_elem(EBPFDriver *self, int map_desc,
    void *key, void *value, uint64_t flags)
{
  return 0;
}

static int
ebpf_null_map_delete_elem(EBPFDriver *self, int map_desc, void *key)
{
  return 0;
}

static int
ebpf_null_map_get_next_key(EBPFDriver *self, int map_desc,
    void *key, void *next_key)
{
  return 0;
}

static void
ebpf_null_close_prog_desc(EBPFDriver *self, int prog_desc)
{
  return;
}

static void
ebpf_null_close_map_desc(EBPFDriver *self, int map_desc)
{
  return;
}

EBPFNullDriver*
ebpf_null_driver_create(void)
{
  struct ebpf_null_driver *driver = malloc(sizeof(struct ebpf_null_driver));
  if (!driver) {
    return NULL;
  }

  driver->base.load_prog = ebpf_null_load_prog;
  driver->base.map_create = ebpf_null_map_create;
  driver->base.map_update_elem = ebpf_null_map_update_elem;
  driver->base.map_lookup_elem = ebpf_null_map_lookup_elem;
  driver->base.map_delete_elem = ebpf_null_map_delete_elem;
  driver->base.map_get_next_key = ebpf_null_map_get_next_key;
  driver->base.close_prog_desc = ebpf_null_close_prog_desc;
  driver->base.close_map_desc = ebpf_null_close_map_desc;

  return driver;
}

void
ebpf_null_driver_destroy(EBPFNullDriver *driver)
{
  free(driver);
}
