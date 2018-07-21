#include <stdint.h>
#include <sys/ebpf_uapi.h>

EBPF_DEFINE_MAP(array, ARRAY, sizeof(uint32_t), sizeof(uint32_t), 100, 0);
EBPF_DEFINE_MAP(hash, HASHTABLE, sizeof(uint32_t), sizeof(uint32_t), 100, 0);

uint64_t
test_prog(void)
{
	int error;
	uint32_t key = 1, *value;

	value = ebpf_map_lookup_elem(&array, &key);
	if (!value) {
		return UINT64_MAX;
	}

	error = ebpf_map_update_elem(&hash, &key, value, 0);
	if (error) {
		return UINT64_MAX;
	}

	return 0;
}
