#include <stdint.h>
#include <sys/ebpf_uapi.h>

__attribute__((section("maps")))
struct ebpf_map_def hash = {
  .type = EBPF_MAP_TYPE_TOMMYHASHTBL,
  .key_size = sizeof(uint32_t),
  .value_size = sizeof(uint32_t),
  .max_entries = 101,
  .flags = 0
};

uint64_t test(void) {
  uint32_t key = 0, *value;

  value = ebpf_map_lookup_elem(&hash, &key, 0);
  if (!value) {
    return UINT64_MAX;
  }

  return *value;
}
