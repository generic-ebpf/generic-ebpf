.PHONY: all clean do_test ebpf_tests ebpf_prog_tests ebpf_map_tests \
	clean_ebpf_tests clean_prog_tests clean_ebpf_map_tests ebpf_tests_do_test \
	ebpf_prog_tests_do_test ebpf_map_tests_do_test

all: ebpf_tests ebpf_prog_tests ebpf_map_tests
clean: clean_ebpf_tests clean_ebpf_prog_tests clean_ebpf_map_tests
do_test: ebpf_tests_do_test ebpf_prog_tests_do_test ebpf_map_tests_do_test

ebpf_tests:
	make -C ebpf_tests

ebpf_prog_tests:
	make -C ebpf_prog_tests

ebpf_map_tests:
	make -C ebpf_map_tests

clean_ebpf_tests:
	make -C ebpf_tests clean

clean_ebpf_prog_tests:
	make -C ebpf_prog_tests clean

clean_ebpf_map_tests:
	make -C ebpf_map_tests clean

ebpf_tests_do_test:
	make -C ebpf_tests do_test

ebpf_prog_tests_do_test:
	make -C ebpf_prog_tests do_test

ebpf_map_tests_do_test:
	make -C ebpf_map_tests do_test
