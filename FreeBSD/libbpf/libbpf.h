#pragma once

#include <sys/ebpf.h>
#include <sys/ebpf_dev.h>

/* glue macros for conpatibility */
#define bpf_insn ebpf_inst
#define bpf_prog_type ebpf_prog_types
#define bpf_map_type ebpf_map_types

extern int bpf_create_map(enum bpf_map_type map_type, const char *name,
                          int key_size, int value_size, int max_entries,
                          int map_flags);
extern int bpf_update_elem(int fd, void *key, void *value,
                           unsigned long long flags);
extern int bpf_lookup_elem(int fd, void *key, void *value,
                           unsigned long long flags);
extern int bpf_delete_elem(int fd, void *key);
extern int bpf_get_next_key(int fd, void *key, void *next_key);

extern int bpf_prog_load(enum bpf_prog_type prog_type, const char *name,
                         const struct bpf_insn *insns, int insn_len,
                         const char *license, unsigned kern_version,
                         int log_level, char *log_buf, unsigned log_buf_size);
