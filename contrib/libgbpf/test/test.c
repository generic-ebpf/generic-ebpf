#include <stdint.h>
#include <sys/ebpf_uapi.h>

EBPF_DEFINE_MAP(array,"array", sizeof(uint32_t), sizeof(uint32_t), 100, 0);
EBPF_DEFINE_MAP(hash, "hashtable", sizeof(uint32_t), sizeof(uint32_t), 100, 0);
EBPF_DEFINE_MAP(pcpu_array,"percpu_array", sizeof(uint32_t), sizeof(uint32_t), 100, 0);
EBPF_DEFINE_MAP(pcpu_hash, "percpu_hashtable", sizeof(uint32_t), sizeof(uint32_t), 100, 0);

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

	value = ebpf_map_lookup_elem(&pcpu_array, &key);
	if (!value) {
		return UINT64_MAX;
	}

	error = ebpf_map_update_elem(&pcpu_hash, &key, value, 0);
	if (error) {
		return UINT64_MAX;
	}

	return 0;
}
