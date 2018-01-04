#pragma once

enum ebpf_prog_types {
  EBPF_PROG_TYPE_TEST = 0,
  __EBPF_PROG_TYPE_MAX
};

enum ebpf_map_types {
  EBPF_MAP_TYPE_ARRAY = 0,
  EBPF_MAP_TYPE_TOMMYHASHTBL,
  __EBPF_MAP_TYPE_MAX
};

#define EBPF_PSEUDO_MAP_DESC 1
#define EBPF_PROG_MAX_ATTACHED_MAPS 64
