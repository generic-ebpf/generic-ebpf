#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <sys/ioctl.h>

#include <sys/ebpf.h>
#include <sys/ebpf_dev.h>
#include <gbpf/gbpf.h>

enum map_type { ARRAY, HASHTABLE };

enum key_mode { RANDOM, FORWARD };

#define HASH_KEY_BASE 0x80000000
#define VAL_SIZE 16

struct obj {
	uint8_t val[VAL_SIZE];
};

static struct obj *objs;
static uint32_t *insert_keys;
static uint32_t *search_keys;

void
die(const char *msg)
{
	perror(msg);
	exit(EXIT_FAILURE);
}

void
shuffle(uint32_t ary[], size_t size)
{
	srand((unsigned)time(NULL));
	for (uint32_t i = 0; i < size; i++) {
		uint32_t j = rand() % size;
		uint32_t t = ary[i];
		ary[i] = ary[j];
		ary[j] = t;
	}
}

void
abort_benchmark(const char *bench_name)
{
	fprintf(stderr, "Error occured while %s benchmark\n", bench_name);
	exit(EXIT_FAILURE);
}

void
init_objs(uint32_t nobjs)
{
	objs = (struct obj *)calloc(nobjs, sizeof(struct obj));
	if (!objs) {
		die("calloc");
	}
}

void
deinit_objs(void)
{
	free(objs);
}

void
init_array_keys(int mode, uint32_t nobjs)
{
	for (uint32_t i = 0; i < nobjs; i++) {
		insert_keys[i] = i;
		search_keys[i] = i;
	}
}

void
init_hash_keys(int mode, uint32_t nobjs)
{
	for (uint32_t i = 0; i < nobjs; i++) {
		insert_keys[i] = HASH_KEY_BASE + i * 2;
		search_keys[i] = HASH_KEY_BASE + i * 2;
	}
}

void
init_keys(int map_type, int mode, uint32_t nobjs)
{
	insert_keys = (uint32_t *)calloc(sizeof(uint32_t), nobjs);
	if (!insert_keys) {
		die("calloc");
	}

	search_keys = (uint32_t *)calloc(sizeof(uint32_t), nobjs);
	if (!search_keys) {
		die("calloc");
	}

	switch (map_type) {
	case ARRAY:
		init_array_keys(mode, nobjs);
		break;
	case HASHTABLE:
		init_hash_keys(mode, nobjs);
		break;
	default:
		fprintf(stderr, "Unknown map type\n");
		exit(EXIT_FAILURE);
	}

	if (mode == RANDOM) {
		shuffle(insert_keys, nobjs);
		shuffle(search_keys, nobjs);
	}
}

void
deinit_keys(void)
{
	free(insert_keys);
	free(search_keys);
}

void
run_insert_benchmark(GBPFDriver *driver, int mapfd, uint32_t nobjs)
{
	int error;
	uint32_t k;
	struct obj *v;

	for (uint32_t i = 0; i < nobjs; i++) {
		k = insert_keys[i];
		v = objs + i;

		error = gbpf_map_update_elem(driver, mapfd, &k, v, 0);
		if (error) {
			abort_benchmark("insert");
		}
	}
}

void
run_change_benchmark(GBPFDriver *driver, int mapfd, uint32_t nobjs)
{
	int error;
	uint32_t k;
	struct obj v;

	for (uint32_t i = 0; i < nobjs; i++) {
		k = search_keys[i];

		error = gbpf_map_lookup_elem(driver, mapfd, &k, &v);
		if (error) {
			abort_benchmark("change");
		}

		error = gbpf_map_delete_elem(driver, mapfd, &k);
		if (error) {
			abort_benchmark("change");
		}

		k = insert_keys[i] + 1;
		error = gbpf_map_update_elem(driver, mapfd, &k, &v, 0);
		if (error) {
			abort_benchmark("change");
		}
	}
}

void
run_hit_benchmark(GBPFDriver *driver, int mapfd, uint32_t nobjs)
{
	int error;
	uint32_t k;
	struct obj v;

	for (uint32_t i = 0; i < nobjs; i++) {
		k = search_keys[i] + 1;

		error = gbpf_map_lookup_elem(driver, mapfd, &k, &v);
		if (error) {
			abort_benchmark("hit");
		}
	}
}

void
run_miss_benchmark(GBPFDriver *driver, int mapfd, uint32_t nobjs)
{
	int error;
	uint32_t k;
	struct obj v;

	for (uint32_t i = 0; i < nobjs; i++) {
		k = search_keys[i];

		error = gbpf_map_lookup_elem(driver, mapfd, &k, &v);
		if (!error) {
			abort_benchmark("miss");
		}
	}
}

void
run_remove_benchmark(GBPFDriver *driver, int mapfd, uint32_t nobjs)
{
	int error;
	uint32_t k;
	struct obj v;

	for (uint32_t i = 0; i < nobjs; i++) {
		k = search_keys[i] + 1;

		error = gbpf_map_lookup_elem(driver, mapfd, &k, &v);
		if (error) {
			abort_benchmark("remove");
		}

		error = gbpf_map_delete_elem(driver, mapfd, &k);
		if (error) {
			abort_benchmark("remove");
		}
	}
}

uint64_t
measure(GBPFDriver *driver, int mapfd, uint32_t nobjs,
	void (*bench)(GBPFDriver *driver, int mapfd, uint32_t nobjs))
{
	struct timeval tv0, tv1;

	gettimeofday(&tv0, NULL);
	bench(driver, mapfd, nobjs);
	gettimeofday(&tv1, NULL);

	uint64_t t1 =
	    (uint64_t)(tv0.tv_sec * 1000000) + (uint64_t)(tv0.tv_usec);
	uint64_t t2 =
	    (uint64_t)(tv1.tv_sec * 1000000) + (uint64_t)(tv1.tv_usec);

	return t2 - t1;
}

void
run_benchmark(GBPFDriver *driver, int mapfd, int map_type, int mode,
	      uint32_t nobjs)
{
	uint64_t result;
	const char *fmt = "%d,%s,%d,%u,%ld\n";

	init_objs(nobjs);
	init_keys(map_type, mode, nobjs);

	result = measure(driver, mapfd, nobjs, run_insert_benchmark);
	printf(fmt, map_type, "insert", mode, nobjs, result);
	result = measure(driver, mapfd, nobjs, run_change_benchmark);
	printf(fmt, map_type, "change", mode, nobjs, result);
	result = measure(driver, mapfd, nobjs, run_hit_benchmark);
	printf(fmt, map_type, "hit", mode, nobjs, result);
	result = measure(driver, mapfd, nobjs, run_miss_benchmark);
	printf(fmt, map_type, "miss", mode, nobjs, result);
	result = measure(driver, mapfd, nobjs, run_remove_benchmark);
	printf(fmt, map_type, "remove", mode, nobjs, result);

	deinit_keys();
	deinit_objs();
}

int
main(void)
{
	uint16_t type_array, type_hashtable;
	GBPFDriver *driver;

#ifdef linux
#ifdef native_bpf
	driver = (GBPFDriver *)gbpf_linux_driver_create();
	if (!driver) {
		die("gbpf_linux_driver_create");
	}
	type_array = BPF_MAP_TYPE_ARRAY;
	type_hashtable = BPF_MAP_TYPE_HASH;
#else
	driver = (GBPFDriver *)ebpf_dev_driver_create();
	if (!driver) {
		die("ebpf_dev_driver_create");
	}
	type_array = EBPF_MAP_TYPE_ARRAY;
	type_hashtable = EBPF_MAP_TYPE_HASHTABLE;
#endif
#elif defined(__FreeBSD__)
	driver = (GBPFDriver *)ebpf_dev_driver_create();
	if (!driver) {
		die("ebpf_dev_driver_create");
	}
	type_array = EBPF_MAP_TYPE_ARRAY;
	type_hashtable = EBPF_MAP_TYPE_HASHTABLE;
#else
#error Unsupported platform
#endif

	int mapfd;
	uint32_t nobjs;

	printf("type,bench,mode,nobjs,time\n");

	for (uint32_t i = 1; i <= 100; i++) {
		nobjs = 1000 * i;
		mapfd =
		    gbpf_map_create(driver, type_hashtable, sizeof(uint32_t),
				    sizeof(struct obj), nobjs, 0);
		if (mapfd < 0) {
			die("ebpf_map_create");
		}
		run_benchmark(driver, mapfd, HASHTABLE, RANDOM, nobjs);
		close(mapfd);
	}

	for (uint32_t i = 1; i <= 100; i++) {
		nobjs = 1000 * i;
		mapfd =
		    gbpf_map_create(driver, type_hashtable, sizeof(uint32_t),
				    sizeof(struct obj), nobjs, 0);
		if (mapfd < 0) {
			die("ebpf_map_create");
		}
		run_benchmark(driver, mapfd, HASHTABLE, FORWARD, nobjs);
		close(mapfd);
	}

#ifdef linux
#ifdef native_bpf
	gbpf_linux_driver_destroy((GBPFLinuxDriver *)driver);
	printf("Benchmark for Linux native bpf map finished\n");
#else
	ebpf_dev_driver_destroy((EBPFDevDriver *)driver);
	printf("Benchmark for generic-ebpf-Linux map finished\n");
#endif
#elif defined(__FreeBSD__)
	ebpf_dev_driver_destroy((EBPFDevDriver *)driver);
	printf("Benchmark for generic-ebpf-FreeBSD map finished\n");
#endif

	return EXIT_SUCCESS;
}
