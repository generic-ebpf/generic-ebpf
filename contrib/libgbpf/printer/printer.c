#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

#include <sys/ebpf_inst.h>
#include <sys/ebpf_uapi.h>
#include <gbpf/gbpf.h>

void
printer_on_prog(GBPFElfWalker *walker, const char *name, struct ebpf_inst *prog,
		uint32_t prog_len)
{
	printf("Find Program!\nname: %s\n", name);
}

void
printer_on_map(GBPFElfWalker *walker, const char *name, int desc,
	       struct ebpf_map_def *map)
{
	printf("Find Map!\nname: %s desc: %d type: %d key_size: %u value_size: "
	       "%u max_entries: %u\n",
	       name, desc, map->type, map->key_size, map->value_size,
	       map->max_entries);
}

int
main(void)
{
	int error;

	GBPFNullDriver *driver = gbpf_null_driver_create();
	assert(driver);

	GBPFElfWalker walker = {
	    .on_prog = printer_on_prog, .on_map = printer_on_map, .data = NULL};

	error = gbpf_walk_elf(&walker, (GBPFDriver *)driver, "test.o");
	assert(!error);

	return EXIT_SUCCESS;
}
