#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <gelf.h>
#include <assert.h>
#include <sys/ioctl.h>

#include <sys/ebpf_inst.h>
#include <sys/ebpf_uapi.h>

#include "ebpf_elf_loader.h"

#define FOUND_PROG(loader)               (loader)->found_prog
#define MARK_PROG_FOUND(loader)          ((loader)->found_prog = true)
#define FOUND_MAPS(loader)               (loader)->found_maps
#define MARK_MAPS_FOUND(loader)          ((loader)->found_maps = true)
#define FOUND_SYMBOLS(loader)            (loader)->found_symbols
#define MARK_SYMBOLS_FOUND(loader)       ((loader)->found_symbols = true)
#define FOUND_RELOCATIONS(loader)        (loader)->found_relocations
#define MARK_RELOCATIONS_FOUND(loader)   ((loader)->found_relocations = true)

struct ebpf_inst*
ebpf_loader_get_prog(EBPFLoader *loader)
{
  if (!FOUND_PROG(loader)) {
    return NULL;
  }
  return loader->prog->d_buf;
}

uint32_t
ebpf_loader_get_proglen(EBPFLoader *loader)
{
  if (!FOUND_PROG(loader)) {
    return 0;
  }
  return loader->prog->d_size / sizeof(struct ebpf_inst);
}

int
ebpf_loader_get_map_entries(EBPFLoader *loader,
    struct ebpf_map_entry ***entries, uint16_t *num_map)
{
  if (!FOUND_MAPS(loader)) {
    return -1;
  }

  *entries = loader->map_entries;
  *num_map = loader->num_map;

  return 0;
}

EBPFLoader*
ebpf_loader_create(void)
{
  EBPFLoader *ret = malloc(sizeof(EBPFLoader));
  if (!ret) {
    return NULL;
  }
  memset(ret, 0, sizeof(EBPFLoader));
  return ret;
}

void
ebpf_loader_destroy(EBPFLoader *loader)
{
  for (int i = 0; i < loader->num_map; i++) {
    free(loader->map_entries[i]);
  }
  free(loader);
}
  
static int
find_required_section(EBPFLoader *loader, GElf_Ehdr *ehdr, Elf_Scn *scn)
{
  GElf_Shdr shdr, *shdrp;

  shdrp = gelf_getshdr(scn, &shdr);
  if (!shdrp) {
    return -1;
  }

  if (!FOUND_SYMBOLS(loader) && shdr.sh_type == SHT_SYMTAB) {
    loader->symbols = elf_getdata(scn, 0);
    MARK_SYMBOLS_FOUND(loader);
    return 0;
  }

  char *shname = elf_strptr(loader->elf, ehdr->e_shstrndx, shdr.sh_name);
  if (!shname) {
    return -1;
  }

  D("Found section name: %s", shname);

  if (!FOUND_PROG(loader) && strcmp(shname, PROG_SEC) == 0) {
    loader->prog = elf_getdata(scn, 0);
    MARK_PROG_FOUND(loader);
    return 0;
  }

  if (!FOUND_MAPS(loader) && strcmp(shname, MAP_SEC) == 0) {
    loader->maps = elf_getdata(scn, 0);
    MARK_MAPS_FOUND(loader);
    return 0;
  }

  if (!FOUND_RELOCATIONS(loader) && strcmp(shname, RELOC_SEC) == 0) {
    loader->relocations = elf_getdata(scn, 0);
    MARK_RELOCATIONS_FOUND(loader);
    return 0;
  }

  return 0;
}

static int
resolve_map_relocations(EBPFLoader *loader, GElf_Ehdr *ehdr)
{
  uint8_t *mapdata = loader->maps->d_buf;
  struct ebpf_inst *inst, *insts = loader->prog->d_buf;
  struct ebpf_map_def *map;
  struct ebpf_map_entry *entry;
  char *symname;
  GElf_Rel rel;
  GElf_Sym sym;

  for (int i = 0; gelf_getrel(loader->relocations, i, &rel); i++) {
    gelf_getsym(loader->symbols, GELF_R_SYM(rel.r_info), &sym);

    symname = elf_strptr(loader->elf, ehdr->e_shstrndx, sym.st_name);
    if (!symname) {
      goto err0;
    }

    inst = insts + rel.r_offset / sizeof(struct ebpf_inst);

    if (inst->opcode == EBPF_OP_LDDW) {
      map = (struct ebpf_map_def *)(mapdata + sym.st_value);

      D("Found map relocation entry. It's definition is\n"
        "  Type: %u KeySize: %u ValueSize: %u MaxEntries: %u Flags: %u",
        map->type, map->key_size, map->value_size, map->max_entries, map->flags);

      if (loader->num_map != EBPF_PROG_MAX_ATTACHED_MAPS) {
        entry = malloc(sizeof(struct ebpf_map_entry));
        if (!entry) {
          goto err0;
        }

        entry->name = symname;
        entry->lddw_ptr = inst;
        entry->def = map;

        loader->map_entries[loader->num_map] = entry;
        loader->num_map++;
      }

      continue;
    }

    D("Unknown type relocation entry. name: %s r_offset: %lu",
        symname, rel.r_offset);
  }

  return 0;

err0:
  for (int i = 0; i < loader->num_map; i++) {
    free(loader->map_entries[i]);
  }
  return -1;
}

int
ebpf_load_elf(EBPFLoader *loader, char *fname)
{
  int error;

  int fd = open(fname, O_RDONLY);
  if (fd < 0) {
    return -1;
  }

  if (elf_version(EV_CURRENT) == EV_NONE) {
    D("Invalid elf version");
    goto err0;
  }

  loader->elf = elf_begin(fd, ELF_C_READ, NULL);
  if (!loader->elf) {
    D("%s", elf_errmsg(elf_errno()));
    goto err0;
  }

  GElf_Ehdr ehdr;
  if (gelf_getehdr(loader->elf, &ehdr) != &ehdr) {
    D("%s", elf_errmsg(elf_errno()));
    goto err1;
  }

  Elf_Scn *cur;
  for (int i = 1; i < ehdr.e_shnum; i++) {
    cur = elf_getscn(loader->elf, i);
    if (!cur) {
      D("%s", elf_errmsg(elf_errno()));
      goto err1;
    }

    error = find_required_section(loader, &ehdr, cur);
    if (error) {
      goto err1;
    }
  }

  if (!FOUND_PROG(loader)) {
    D("Error: " PROG_SEC " missing");
    goto err1;
  }

  if (FOUND_RELOCATIONS(loader) && FOUND_SYMBOLS(loader) && FOUND_MAPS(loader)) {
    error = resolve_map_relocations(loader, &ehdr);
    if (error) {
      D("%s", elf_errmsg(elf_errno()));
      goto err1;
    }
  }

  close(fd);

  return 0;

err1:
  elf_end(loader->elf);
err0:
  close(fd);
  return -1;
}
