#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>

#include <sys/ebpf.h>
#include <sys/ebpf_dev.h>
#include "libbpf_ebpf_dev.h"
#include "ebpf_elf_loader.h"

int main(void) {
  int error;
  struct ebpf_elf_loader_ctx ctx;

  char *ftable[] = {
    "ebpf_map_update_elem",
    "ebpf_map_lookup_elem",
    "ebpf_map_delete_elem",
    NULL
  };

  ebpf_elf_loader_init(&ctx, "./test.o", ftable);

  int prog_fd;
  prog_fd = ebpf_elf_load(&ctx);
  if (prog_fd < 0) {
    perror("ebpf_elf_load");
  }

  struct map_entry *hash = ebpf_elf_loader_lookup_map_entry(&ctx, "hash");
  assert(hash);

  uint32_t key = 0, value = 12345;
  error = ebpf_map_update_elem(ctx.ebpf_fd, hash->fd, &key, &value, 0);
  assert(!error);

  uint64_t context = 1000, result;
  error = ebpf_run_test(ctx.ebpf_fd, prog_fd, &context,
      sizeof(uint64_t), 0, &result);
  if (error < 0) {
    perror("ebpf_run_test");
  }

  printf("result %lu\n", result);

  ebpf_elf_loader_deinit(&ctx);

  return 0;
}
