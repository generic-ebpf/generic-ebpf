all clean:
	for D in ${SUBDIR}; do (cd $$D && make $@); done
check:
	for D in ${SUBDIR_C}; do (cd $$D && make $@); done
.PHONY: all clean check

SUBDIR=	ebpf_tests \
	ebpf_prog_tests \
	ebpf_map_tests \
	ebpf_dev_tests

SUBDIR_C= \
	ebpf_prog_tests \
	ebpf_map_tests \
	ebpf_dev_tests
