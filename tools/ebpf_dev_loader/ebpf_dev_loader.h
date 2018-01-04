#pragma once

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <gelf.h>
#include <sys/ioctl.h>
#include <assert.h>

#include <sys/ebpf_inst.h>
#include <sys/ebpf_uapi.h>
#include <sys/ebpf_dev.h>

struct map_entry {
  char *name;
  int fd;
};

struct ebpf_dev_loader_ctx {
  char *fname;
  bool found_prog;
  bool found_map;
  bool found_symtab;
  bool found_prog_reloc;
  Elf *elf;
  GElf_Ehdr *ehdr;
  GElf_Shdr *prog_shdr;
  Elf_Data *prog_data;
  GElf_Shdr *map_shdr;
  Elf_Data *map_data;
  GElf_Shdr *symtab;
  Elf_Data *symbols;
  GElf_Shdr *prog_reloc;
  Elf_Data *prog_reloc_data;
  char **func_table;
  int ebpf_fd;
  struct map_entry *maps[EBPF_PROG_MAX_ATTACHED_MAPS];
  uint16_t num_map;
};

static struct map_entry*
ebpf_elf_loader_lookup_map_entry(struct ebpf_dev_loader_ctx *ctx, const char *name)
{
  for (int i = 0; i < ctx->num_map; i++) {
    if (strcmp(name, ctx->maps[i]->name) == 0) {
      return ctx->maps[i];
    }
  }
  return NULL;
}

#define PROG_SEC    ".text"
#define MAP_SEC     "map"
#define PROG_RELOC_SEC ".rel"PROG_SEC

#define FOUND_PROG(ctx)             (ctx)->found_prog
#define MARK_PROG_FOUND(ctx)        ((ctx)->found_prog = true)
#define FOUND_MAP(ctx)              (ctx)->found_map
#define MARK_MAP_FOUND(ctx)         ((ctx)->found_map = true)
#define FOUND_SYMTAB(ctx)           (ctx)->found_symtab
#define MARK_SYMTAB_FOUND(ctx)      ((ctx)->found_symtab = true)
#define FOUND_PROG_RELOC(ctx)       (ctx)->found_prog_reloc
#define MARK_PROG_RELOC_FOUND(ctx)  ((ctx)->found_prog_reloc = true)

#ifdef DEBUG
#define D(_fmt, ...) fprintf(stderr, _fmt "\n", ##__VA_ARGS__)
#else
#define D(_fmt, ...) ;
#endif

static void
ebpf_elf_loader_init(struct ebpf_dev_loader_ctx *ctx, char *fname, char **func_table)
{
  memset(ctx, 0, sizeof(struct ebpf_dev_loader_ctx));
  ctx->fname = fname;
  ctx->func_table = func_table;
  ctx->ebpf_fd = ebpf_dev_init();
}

static void
ebpf_elf_loader_deinit(struct ebpf_dev_loader_ctx *ctx)
{
  if (FOUND_PROG(ctx)) {
    free(ctx->prog_shdr);
    free(ctx->prog_data);
  }

  if (FOUND_MAP(ctx)) {
    free(ctx->map_shdr);
    free(ctx->map_data);
  }

  if (FOUND_SYMTAB(ctx)) {
    free(ctx->symtab);
    free(ctx->symbols);
  }

  if (FOUND_PROG_RELOC(ctx)) {
    free(ctx->prog_reloc);
    free(ctx->prog_reloc_data);
  }

  for (int i = 0; i < ctx->num_map; i++) {
    free(ctx->maps[i]->name);
    close(ctx->maps[i]->fd);
    free(ctx->maps[i]);
  }

  ebpf_dev_deinit(ctx->ebpf_fd);
}

static int
handle_section(struct ebpf_dev_loader_ctx *ctx, GElf_Ehdr *ehdr, Elf *elf, int idx)
{
  Elf_Scn *scn;
  scn = elf_getscn(elf, idx);
  if (!scn) {
    return -1;
  }

  GElf_Shdr *shdr = malloc(sizeof(GElf_Shdr));
  shdr = gelf_getshdr(scn, shdr);
  if (!shdr) {
    free(shdr);
    return -1;
  }

  if (!FOUND_SYMTAB(ctx) && shdr->sh_type == SHT_SYMTAB) {
    ctx->symtab = shdr;
    ctx->symbols = elf_getdata(scn, 0);
    MARK_SYMTAB_FOUND(ctx);
    return 0;
  }

  Elf_Data *data;
  char *shname = elf_strptr(elf, ehdr->e_shstrndx, shdr->sh_name);
  if (!shname) {
    free(shdr);
    return -1;
  }

  if (!FOUND_PROG(ctx) && strcmp(shname, PROG_SEC) == 0) {
    ctx->prog_shdr = shdr;
    ctx->prog_data = elf_getdata(scn, 0);
    MARK_PROG_FOUND(ctx);
    return 0;
  }

  if (!FOUND_MAP(ctx) && strcmp(shname, MAP_SEC) == 0) {
    ctx->map_shdr = shdr;
    ctx->map_data = elf_getdata(scn, 0);
    MARK_MAP_FOUND(ctx);
    return 0;
  }

  if (!FOUND_PROG_RELOC(ctx) && strcmp(shname, PROG_RELOC_SEC) == 0) {
    ctx->prog_reloc = shdr;
    ctx->prog_reloc_data = elf_getdata(scn, 0);
    MARK_PROG_RELOC_FOUND(ctx);
    return 0;
  }

  // don't have to remember this section
  free(shdr);

  return 0;
}

static int
resolve_relocation(struct ebpf_dev_loader_ctx *ctx)
{
  GElf_Shdr *prog_reloc = ctx->prog_reloc;
  Elf_Data *prog_reloc_data = ctx->prog_reloc_data;
  char **func_table = ctx->func_table;

  int numrels = prog_reloc->sh_size / prog_reloc->sh_entsize;
  if (numrels == 0) {
    D("relocation section is empty");
    return 0;
  }

  GElf_Rel rel;
  GElf_Sym sym;
  struct ebpf_inst *inst, *insts = ctx->prog_data->d_buf;
  for (int i = 0; i < numrels; i++) {
    gelf_getrel(prog_reloc_data, i, &rel);
    gelf_getsym(ctx->symbols, GELF_R_SYM(rel.r_info), &sym);

    char *symname = elf_strptr(ctx->elf, ctx->ehdr->e_shstrndx, sym.st_name);
    if (!symname) {
      return -1;
    }

    inst = insts + rel.r_offset / sizeof(struct ebpf_inst);

    int func_idx = -1;
    for (int i = 0; func_table[i] != NULL; i++) {
      if (strcmp(symname, func_table[i]) == 0) {
        func_idx = i;
        break;
      }
    }

    if (func_idx != -1) {
      if (inst->opcode != EBPF_OP_CALL) {
        D("Invalid function call");
        return -1;
      }

      inst->imm = func_idx;
      D("Successfully relocated function call. %s index: %u\n", symname, func_idx);
      continue;
    }

    if (inst->opcode == EBPF_OP_LDDW) {
      if (!FOUND_MAP(ctx)) {
        D("Map section is not found. What is this?");
        return -1;
      }

      uint8_t *mapdata = ctx->map_data->d_buf;
      struct ebpf_map_def *map = (struct ebpf_map_def *)(mapdata + sym.st_value);
      D("Found map relocation entry. It's definition is\n"
             "  Type: %u KeySize: %u ValueSize: %u MaxEntries: %u Flags: %u\n",
             map->type, map->key_size, map->value_size, map->max_entries, map->flags);

      int mapfd = ebpf_dev_map_create(ctx->ebpf_fd, map->type, map->key_size,
          map->value_size, map->max_entries, map->flags);
      assert(mapfd > 0);
      if (ctx->num_map != EBPF_PROG_MAX_ATTACHED_MAPS) {
        struct map_entry *ent = calloc(sizeof(struct map_entry), 1);
        ent->name = strdup(symname);
        ent->fd = mapfd;
        ctx->maps[ctx->num_map] = ent;
        ctx->num_map++;
        D("Registered map entry. name: %s fd: %d", ent->name, ent->fd);
      }

      // assume create map success
      inst->imm = mapfd;
      inst->src = EBPF_PSEUDO_MAP_DESC;
      continue;
    }

    D("Unknown type relocation entry. name: %s r_offset: %lu\n", symname, rel.r_offset);
  }

  return 0;
}

static int
ebpf_elf_load(struct ebpf_dev_loader_ctx *ctx)
{
  int error;

  int fd = open(ctx->fname, O_RDWR);
  if (fd < 0) {
    return -1;
  }

  if (elf_version(EV_CURRENT) == EV_NONE) {
    D("Invalid elf version");
    return -1;
  }

  Elf *elf = elf_begin(fd, ELF_C_READ, NULL);
  if (!elf) {
    D("%s", elf_errmsg(elf_errno()));
    return -1;
  }
  ctx->elf = elf;

  GElf_Ehdr ehdr;
  if (gelf_getehdr(elf, &ehdr) != &ehdr) {
    D("%s", elf_errmsg(elf_errno()));
    return -1;
  }
  ctx->ehdr = &ehdr;

  for (int i = 1; i < ehdr.e_shnum; i++) {
    error = handle_section(ctx, &ehdr, elf, i);
    if (error) {
      D("Error occured while parsing sections");
      return -1;
    }
  }

  if (!FOUND_SYMTAB(ctx)) {
    D("Error: Symtab missing");
    return -1;
  }

  if (!FOUND_PROG(ctx)) {
    D("Error: " PROG_SEC " missing");
    return -1;
  }

  if (FOUND_PROG_RELOC(ctx)) {
    resolve_relocation(ctx);
  }

  elf_end(elf);

  return ebpf_dev_load_prog(ctx->ebpf_fd, EBPF_PROG_TYPE_TEST, ctx->prog_data->d_buf,
      ctx->prog_data->d_size / sizeof(struct ebpf_inst));
}
