#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <sys/ioctl.h>
#include <gelf.h>

#include <sys/ebpf_inst.h>
#include <sys/ebpf_uapi.h>

#ifdef DEBUG
#define D(_fmt, ...) fprintf(stderr, _fmt "\n", ##__VA_ARGS__)
#else
#define D(_fmt, ...) ;
#endif

#define PROG_SEC    ".text"
#define MAP_SEC     "maps"
#define RELOC_SEC ".rel"PROG_SEC

struct ebpf_map_entry {
  char *name;
  struct ebpf_inst *lddw_ptr;
  struct ebpf_map_def *def;
};

typedef struct ebpf_loader_ctx {
  Elf *elf;
  bool found_prog;
  bool found_maps;
  bool found_symbols;
  bool found_relocations;
  Elf_Data *prog;
  Elf_Data *maps;
  Elf_Data *symbols;
  Elf_Data *relocations;
  struct ebpf_map_entry *map_entries[EBPF_PROG_MAX_ATTACHED_MAPS];
  uint16_t num_map;
} EBPFLoader;

EBPFLoader* ebpf_loader_create(void);
int ebpf_load_elf(EBPFLoader *loader, char *fname);
void ebpf_loader_destroy(EBPFLoader *loader);

struct ebpf_inst* ebpf_loader_get_prog(EBPFLoader *loader);
uint32_t ebpf_loader_get_proglen(EBPFLoader *loader);
int ebpf_loader_get_map_entries(EBPFLoader *loader,
    struct ebpf_map_entry ***entries, uint16_t *num_map);
