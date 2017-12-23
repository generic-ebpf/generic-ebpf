#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <errno.h>

#include "libbpf.h"

int
bpf_prog_load(enum bpf_prog_type prog_type, const char *name,
              const struct bpf_insn *insns, int insn_len, const char *license,
              unsigned kern_version, int log_level, char *log_buf,
              unsigned log_buf_size)
{
    int ret, err, ebpf_fd;

    ebpf_fd = open("/dev/ebpf", O_RDWR);
    if (ebpf_fd < 0) {
        return -1;
    }

    union ebpf_req req = {.prog_fdp = &ret,
                          .prog_type = prog_type,
                          .prog_len = insn_len * sizeof(struct bpf_insn),
                          .prog = (void *)insns};

    err = ioctl(ebpf_fd, EBPFIOC_LOAD_PROG, &req);
    if (err < 0) {
        close(ebpf_fd);
        return -1;
    }

    close(ebpf_fd);

    return ret;
}

int
bpf_create_map(enum bpf_map_type map_type, const char *name, int key_size,
               int value_size, int max_entries, int map_flags)
{
    int ret, err, ebpf_fd;

    ebpf_fd = open("/dev/ebpf", O_RDWR);
    if (ebpf_fd < 0) {
        return -1;
    }

    union ebpf_req req = {.map_fdp = &ret,
                          .map_type = map_type,
                          .key_size = key_size,
                          .value_size = value_size,
                          .max_entries = max_entries,
                          .map_flags = map_flags};

    err = ioctl(ebpf_fd, EBPFIOC_MAP_CREATE, &req);
    if (err < 0) {
        close(ebpf_fd);
        return -1;
    }

    close(ebpf_fd);

    return ret;
}

int
bpf_lookup_elem(int fd, void *key, void *value, unsigned long long flags)
{
    int ebpf_fd, err;

    ebpf_fd = open("/dev/ebpf", O_RDWR);
    if (fd < 0) {
        return -1;
    }

    union ebpf_req req = {.map_fd = fd,
                          .key = (uint64_t)key,
                          .value = (uint64_t)value,
                          .flags = flags};

    err = ioctl(ebpf_fd, EBPFIOC_MAP_LOOKUP_ELEM, &req);
    if (err < 0) {
        close(ebpf_fd);
        return -1;
    }

    close(ebpf_fd);

    return 0;
}

int
bpf_update_elem(int fd, void *key, void *value, unsigned long long flags)
{
    int ebpf_fd, err;

    ebpf_fd = open("/dev/ebpf", O_RDWR);
    if (ebpf_fd < 0) {
        return -1;
    }

    union ebpf_req req = {.map_fd = fd,
                          .key = (uint64_t)key,
                          .value = (uint64_t)value,
                          .flags = flags};

    err = ioctl(ebpf_fd, EBPFIOC_MAP_UPDATE_ELEM, &req);
    if (err < 0) {
        close(ebpf_fd);
        return -1;
    }

    close(ebpf_fd);

    return 0;
}

int
bpf_delete_elem(int fd, void *key)
{
    int ebpf_fd, err;

    ebpf_fd = open("/dev/ebpf", O_RDWR);
    if (ebpf_fd < 0) {
        return -1;
    }

    union ebpf_req req = {.map_fd = fd, .key = (uint64_t)key};

    err = ioctl(ebpf_fd, EBPFIOC_MAP_DELETE_ELEM, &req);
    if (err < 0) {
        close(ebpf_fd);
        return -1;
    }

    close(ebpf_fd);

    return 0;
}

int
bpf_get_next_key(int fd, void *key, void *next_key)
{
    int ebpf_fd, err;

    ebpf_fd = open("/dev/ebpf", O_RDWR);
    if (ebpf_fd < 0) {
        return -1;
    }

    union ebpf_req req = {
        .map_fd = fd, .key = (uint64_t)key, .next_key = (uint64_t)next_key};

    err = ioctl(ebpf_fd, EBPFIOC_MAP_GET_NEXT_KEY, &req);
    if (err < 0) {
        close(ebpf_fd);
        return -1;
    }

    close(ebpf_fd);

    return 0;
}
