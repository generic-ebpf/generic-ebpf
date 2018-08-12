#pragma once

#include <stdint.h>

static int
ebpf_init(void)
{
	return open("/dev/ebpf", O_RDWR);
}

static void
ebpf_done(int ebpf_fd)
{
	close(ebpf_fd);
}

static int
ebpf_load_prog(int ebpf_fd, uint16_t prog_type, void *prog, uint32_t prog_len)
{
	int fd, error;

	union ebpf_req req;
	req.prog_fdp = &fd;
	req.prog_type = prog_type;
	req.prog_len = prog_len;
	req.prog = prog;

	error = ioctl(ebpf_fd, EBPFIOC_LOAD_PROG, &req);
	if (error) {
		return error;
	}

	return fd;
}

static int
ebpf_map_create(int ebpf_fd, uint16_t type, uint32_t key_size,
		uint32_t value_size, uint32_t max_entries, uint32_t map_flags)
{
	int fd, error;

	union ebpf_req req;
	req.map_fdp = &fd;
	req.map_type = type;
	req.key_size = key_size;
	req.value_size = value_size;
	req.max_entries = max_entries;
	req.map_flags = map_flags;

	error = ioctl(ebpf_fd, EBPFIOC_MAP_CREATE, &req);
	if (error) {
		return error;
	}

	return fd;
}

static int
ebpf_map_update_elem(int ebpf_fd, int map_fd, void *key, void *value,
		     uint64_t flags)
{
	int error;

	union ebpf_req req;
	req.map_fd = map_fd;
	req.key = key;
	req.value = value;
	req.flags = flags;

	return ioctl(ebpf_fd, EBPFIOC_MAP_UPDATE_ELEM, &req);
}

static int
ebpf_map_lookup_elem(int ebpf_fd, int map_fd, void *key, void *value,
		     uint64_t flags)
{
	int error;

	union ebpf_req req;
	req.map_fd = map_fd;
	req.key = key;
	req.value = value;
	req.flags = flags;

	return ioctl(ebpf_fd, EBPFIOC_MAP_LOOKUP_ELEM, &req);
}

static int
ebpf_map_delete_elem(int ebpf_fd, int map_fd, void *key)
{
	int error;

	union ebpf_req req;
	req.map_fd = map_fd;
	req.key = key;

	return ioctl(ebpf_fd, EBPFIOC_MAP_DELETE_ELEM, &req);
}

static int
ebpf_map_get_next_key(int ebpf_fd, int map_fd, void *key, void *next_key)
{
	int error;

	union ebpf_req req;
	req.map_fd = map_fd;
	req.key = key;
	req.next_key = next_key;

	return ioctl(ebpf_fd, EBPFIOC_MAP_GET_NEXT_KEY, &req);
}

static int
ebpf_run_test(int ebpf_fd, int prog_fd, void *ctx, uint16_t ctx_len, int jit,
	      uint64_t *result)
{
	union ebpf_req req;
	req.prog_fd = prog_fd;
	req.ctx = ctx;
	req.ctx_len = ctx_len;
	req.jit = jit;
	req.test_result = result;

	return ioctl(ebpf_fd, EBPFIOC_RUN_TEST, &req);
}

static int
ebpf_get_map_type_info(int ebpf_fd, uint16_t mt_id, struct ebpf_map_type_info *mt_info)
{
	union ebpf_req req;
	req.mt_id = mt_id;
	req.mt_info = mt_info;

	return ioctl(ebpf_fd, EBPFIOC_GET_MAP_TYPE_INFO, &req);
}
