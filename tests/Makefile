.PHONY: all clean do_test ebpf_tests ebpf_obj_tests ebpf_map_tests \
	clean_ebpf_tests clean_ebpf_tests clean_ebpf_map_tests ebpf_tests_do_test \
	ebpf_obj_tests_do_test ebpf_map_tests_do_test

all: ebpf_tests ebpf_obj_tests ebpf_map_tests
clean: clean_ebpf_tests clean_ebpf_obj_tests clean_ebpf_map_tests
do_test: ebpf_tests_do_test ebpf_obj_tests_do_test ebpf_map_tests_do_test

ebpf_tests:
	make -C ebpf_tests

ebpf_obj_tests:
	make -C ebpf_obj_tests

ebpf_map_tests:
	make -C ebpf_map_tests

clean_ebpf_tests:
	make -C ebpf_tests clean

clean_ebpf_obj_tests:
	make -C ebpf_obj_tests clean

clean_ebpf_map_tests:
	make -C ebpf_map_tests clean

ebpf_tests_do_test:
	make -C ebpf_tests do_test

ebpf_obj_tests_do_test:
	make -C ebpf_obj_tests do_test

ebpf_map_tests_do_test:
	make -C ebpf_map_tests do_test
