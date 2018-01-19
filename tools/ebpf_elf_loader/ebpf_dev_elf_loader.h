#pragma once

#include "ebpf_elf_loader.h"

int ebpf_dev_load_elf(int ebpf_fd, EBPFLoader *loader, char *fname);

#define EBPF_MAP_FD(_map_entry) _map_entry->lddw_ptr->imm
