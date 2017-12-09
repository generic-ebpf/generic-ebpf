#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/ebpf.h>

#include <dev/ebpf/ebpf_freebsd.h>
#include "libbpf.h"

int 
bpf_prog_load(enum bpf_prog_type prog_type, const char *name,
    const struct bpf_insn *insns, int insn_len,
    const char *license, unsigned kern_version,
    int log_level, char *log_buf, unsigned log_buf_size)
{
  int ret, err, fd;

  fd = open("/dev/ebpf", O_RDWR);
  if (fd < 0) {
    return -1;
  }

  union ebpf_req req = {
    .prog_fd = &ret,
    .prog_type = prog_type,
    .prog_len = insn_len * sizeof(struct bpf_insn),
    .prog = (void *)insns
  };

  err = ioctl(fd, EBPFIOC_LOAD_PROG, &req);
  if (err < 0) {
    close(fd);
    return -1;
  }

  return ret;
}

int main(void) {
  int fd;

  struct ebpf_inst insts[] = {
    { EBPF_OP_MOV64_IMM, 0, 0, 0, 100 },
    { EBPF_OP_EXIT, 0, 0, 0, 0 }
  };

  fd = bpf_prog_load(EBPF_PROG_TYPE_TEST, "test",
      insts, 2, "BSD", 11, 0, NULL, 0);
  if (fd < 0) {
    perror("bpf_prog_load");
    exit(EXIT_FAILURE);
  }

  printf("fd: %d\n", fd);
  close(fd);

  return EXIT_SUCCESS;
}
