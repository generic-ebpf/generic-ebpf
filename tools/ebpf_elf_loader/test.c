#include <stdint.h>
#include <sys/ebpf_uapi.h>

void* ebpf_map_lookup_elem(struct ebpf_map_def *map, void *key, uint64_t flags);

__attribute__((section("map")))
struct ebpf_map_def hash = {
  .type = EBPF_MAP_TYPE_TOMMYHASHTBL,
  .key_size = sizeof(uint32_t),
  .value_size = sizeof(uint32_t),
  .max_entries = 101,
  .flags = 0
};

uint64_t test(void *ctx) {
  uint32_t key = 0, *value;

  value = ebpf_map_lookup_elem(&hash, &key, 0);
  if (!value) {
    return UINT64_MAX;
  }

  return *value;
}
