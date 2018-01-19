#include <stdio.h>
#include <stdint.h>
#include <unistd.h>

#include <sys/ebpf_dev.h>
#include "ebpf_dev_elf_loader.h"

static int
create_map(int ebpf_fd, uint16_t type, uint32_t key_size,
    uint32_t value_size, uint32_t max_entries, uint32_t flags)
{
  int error, mapfd;
  union ebpf_req req;

  req.map_fdp = &mapfd;
  req.map_type = type; 
  req.key_size = key_size;
  req.value_size = value_size;
  req.max_entries = max_entries;
  req.map_flags = flags;

  error = ioctl(ebpf_fd, EBPFIOC_MAP_CREATE, &req);
  if (error) {
    return -1;
  }

  return mapfd;
}

int
ebpf_dev_load_elf(int ebpf_fd, EBPFLoader *loader, char *fname)
{
  int error;

  error = ebpf_load_elf(loader, fname);
  if (error) {
    return -1;
  }

  struct ebpf_map_entry **entry;
  uint16_t num_map;

  error = ebpf_loader_get_map_entries(loader, &entry, &num_map);
  if (error) {
    return -1;
  }

  int mapfd;
  uint16_t i;
  for (i = 0; i < num_map; i++) {
    D("Creating map... Name: %s", entry[i]->name);
    mapfd = create_map(ebpf_fd, entry[i]->def->type, entry[i]->def->key_size,
        entry[i]->def->value_size, entry[i]->def->max_entries,
        entry[i]->def->flags);
    if (mapfd < 0) {
      goto err0;
    }
    entry[i]->lddw_ptr->imm = mapfd;
    entry[i]->lddw_ptr->src = EBPF_PSEUDO_MAP_DESC;
  }

  return 0;

err0:
  for (; i > 0; i--) {
    close(entry[i]->lddw_ptr->imm);
    entry[i]->lddw_ptr->src = 0;
  }

  return -1;
}
