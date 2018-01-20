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

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <gelf.h>

#include <sys/ebpf_inst.h>
#include <sys/ebpf_uapi.h>

#include "ebpf_driver.h"
#include "ebpf_loader.h"

EBPFLoader*
ebpf_loader_create(EBPFDriver *driver)
{
  EBPFLoader *ret = malloc(sizeof(EBPFLoader));
  if (!ret) {
    return NULL;
  }
  memset(ret, 0, sizeof(EBPFLoader));

  ret->driver = driver;

  return ret;
}

static void
cleanup_map_entries(EBPFLoader *loader)
{
  for (int i = 0; i < loader->num_map_entries; i++) {
    loader->driver->close_map_desc(loader->driver, loader->map_entries[i]->map_desc);
    free(loader->map_entries[i]);
  }
}

void
ebpf_loader_destroy(EBPFLoader *loader)
{
  cleanup_map_entries(loader);
  loader->driver->close_prog_desc(loader->driver, loader->prog_desc);
  elf_end(loader->elf);
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

  if (!loader->symbols && shdr.sh_type == SHT_SYMTAB) {
    loader->symbols = elf_getdata(scn, 0);
    return 0;
  }

  char *shname = elf_strptr(loader->elf, ehdr->e_shstrndx, shdr.sh_name);
  if (!shname) {
    return -1;
  }

  D("Found section name: %s", shname);

  if (!loader->prog && strcmp(shname, PROG_SEC) == 0) {
    loader->prog = elf_getdata(scn, 0);
    return 0;
  }

  if (!loader->maps && strcmp(shname, MAP_SEC) == 0) {
    loader->maps = elf_getdata(scn, 0);
    return 0;
  }

  if (!loader->relocations && strcmp(shname, RELOC_SEC) == 0) {
    loader->relocations = elf_getdata(scn, 0);
    return 0;
  }

  return 0;
}

static struct ebpf_map_entry*
ebpf_loader_find_map_entry(EBPFLoader *loader, const char *name)
{
  struct ebpf_map_entry *ret = NULL, **entries = EBPF_MAP_ENTRIES(loader);
  uint16_t num_map_entries = EBPF_NUM_MAP_ENTRIES(loader);

  for (uint16_t i = 0; i < num_map_entries; i++) {
    if (strcmp(name, entries[i]->name) == 0) {
      ret = entries[i];
      break;
    }
  }

  return ret;
}

static int
resolve_relocations(EBPFLoader *loader, GElf_Ehdr *ehdr)
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

      entry = ebpf_loader_find_map_entry(loader, symname);

      if (!entry) {
        if (loader->num_map_entries != EBPF_PROG_MAX_ATTACHED_MAPS) {
          entry = malloc(sizeof(struct ebpf_map_entry));
          if (!entry) {
            goto err0;
          }

          entry->name = symname;
          entry->def = map;
          entry->map_desc = loader->driver->map_create(loader->driver,
              map->type, map->key_size, map->value_size, map->max_entries,
              map->flags);
          if (entry->map_desc < 0) {
            free(entry);
            goto err0;
          }

          loader->map_entries[loader->num_map_entries] = entry;
          loader->num_map_entries++;
        }
      }

      inst->imm = entry->map_desc;
      inst->src = EBPF_PSEUDO_MAP_DESC;

      continue;
    }

    D("Unknown type relocation entry. name: %s r_offset: %lu",
        symname, rel.r_offset);
  }

  return 0;

err0:
  cleanup_map_entries(loader);
  return -1;
}

uint16_t
ebpf_loader_get_map_num(EBPFLoader *loader)
{
  return EBPF_NUM_MAP_ENTRIES(loader);
}

struct ebpf_map_entry*
ebpf_loader_get_map_entry(EBPFLoader *loader, uint16_t idx)
{
  if (idx >= EBPF_NUM_MAP_ENTRIES(loader)) {
    return NULL;
  }
  return EBPF_MAP_ENTRIES(loader)[idx];
}

int
ebpf_loader_execute(EBPFLoader *loader, char *fname, uint16_t prog_type)
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

  if (!loader->prog) {
    D("Error: " PROG_SEC " missing");
    goto err1;
  }

  if (loader->relocations && loader->symbols && loader->maps) {
    error = resolve_relocations(loader, &ehdr);
    if (error) {
      D("%s", elf_errmsg(elf_errno()));
      goto err1;
    }
  }

  close(fd);

  loader->prog_desc = loader->driver->load_prog(loader->driver, prog_type,
      EBPF_PROG(loader), EBPF_PROG_LEN(loader));
  if (loader->prog_desc < 0) {
    goto err2;
  }

  return 0;

err2:
  cleanup_map_entries(loader);
err1:
  elf_end(loader->elf);
err0:
  close(fd);
  return -1;
}
