#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>

#include <sys/ebpf_dev.h>
#include "ebpf_dev_elf_loader.h"
#include "ebpf_dev_lib.h"

struct ebpf_map_entry*
find_map_by_name(const char *name, struct ebpf_map_entry **entries,
    uint16_t num_entries)
{ 
  struct ebpf_map_entry *ret = NULL;
  for (uint16_t i = 0; i < num_entries; i++) {
    ret = entries[i];
    if (strcmp(name, ret->name) == 0) {
      break;
    }
  }
  return ret;
}

int main(void) {
  int error, ebpf_fd;

  EBPFLoader *loader = ebpf_loader_create();
  assert(loader);

  ebpf_fd = ebpf_dev_init();
  assert(ebpf_fd > 0);

  error = ebpf_dev_load_elf(ebpf_fd, loader, "./test.o");
  assert(!error);

  printf("Parsed ELF file. Map symbol relocation "
         "(name hash -> map file descripter) is already done\n\n");

  // load program
  struct ebpf_inst *prog = ebpf_loader_get_prog(loader);
  uint32_t prog_len = ebpf_loader_get_proglen(loader);
  int prog_fd = ebpf_dev_load_prog(ebpf_fd,
      EBPF_PROG_TYPE_TEST, prog, prog_len);
  assert(prog_fd > 0);

  printf("Load program done\n\n");

  struct ebpf_map_entry **entries;
  uint16_t num_map;
  error = ebpf_loader_get_map_entries(loader, &entries, &num_map);
  assert(!error);

  struct ebpf_map_entry *hash = find_map_by_name("hash", entries, num_map);
  assert(hash);

  uint32_t key = 0, value = 12345;
  error = ebpf_dev_map_update_elem(ebpf_fd, EBPF_MAP_FD(hash), &key, &value, 0);
  assert(!error);

  printf("Added entry key: %u value: %u to map named \"hash\"\n\n", key, value);

  uint64_t context = 0, result;
  error = ebpf_dev_run_test(ebpf_fd, prog_fd, &context, sizeof(uint64_t), 0, &result);
  assert(!error);

  printf("We will run test program. The program just read entry key:%u\n"
         "from map \"hash\" and return its value so the test result might be %u\n\n", key, value);

  printf("test result: %lu OK?\n", result);

  close(ebpf_fd);
  ebpf_loader_destroy(loader);

  return EXIT_FAILURE;
}
