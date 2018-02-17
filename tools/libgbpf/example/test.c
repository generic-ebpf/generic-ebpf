#include <stdint.h>
#include <sys/ebpf_uapi.h>

DEFINE_MAP(array, ARRAY, sizeof(uint32_t), sizeof(uint32_t), 100, 0);
DEFINE_MAP(hash, TOMMYHASHTBL, sizeof(uint32_t), sizeof(uint32_t), 100, 0);

uint64_t
test_prog(void)
{
  int error;
  uint32_t key = 1, *value;

  value = map_lookup_elem(&array, &key, 0);
  if (!value) {
    return UINT64_MAX;
  }

  error = map_update_elem(&hash, &key, value, 0);
  if (error) {
    return UINT64_MAX;
  }

  return 0;
}
