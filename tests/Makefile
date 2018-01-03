all: $(platform)_all
clean: $(platform)_clean
do_test: $(platform)_do_test
do_kernel_test: $(platform)_do_kernel_test

clean: clean_ebpf_tests clean_ebpf_prog_tests clean_ebpf_map_tests
do_test: ebpf_tests_do_test ebpf_prog_tests_do_test ebpf_map_tests_do_test
do_kernel_test: ebpf_dev_tests ebpf_dev_do_tests

FreeBSD_all: gtest ebpf_tests ebpf_prog_tests ebpf_map_tests ebpf_dev_tests
Linux_all: gtest ebpf_tests ebpf_prog_tests ebpf_map_tests ebpf_dev_tests
Darwin_all: gtest ebpf_tests ebpf_prog_tests ebpf_map_tests

FreeBSD_clean: clean_gtest clean_ebpf_tests clean_ebpf_prog_tests clean_ebpf_map_tests clean_ebpf_dev_tests
Linux_clean: clean_gtest clean_ebpf_tests clean_ebpf_prog_tests clean_ebpf_map_tests clean_ebpf_dev_tests
Darwin_clean: clean_gtest clean_ebpf_tests clean_ebpf_prog_tests clean_ebpf_map_tests

FreeBSD_do_test: ebpf_tests_do_test ebpf_prog_tests_do_test ebpf_map_tests_do_test
Linux_do_test: ebpf_tests_do_test ebpf_prog_tests_do_test ebpf_map_tests_do_test
Darwin_do_test: ebpf_tests_do_test ebpf_prog_tests_do_test ebpf_map_tests_do_test

FreeBSD_do_kernel_test: ebpf_dev_tests_do_test
Linux_do_kernel_test: ebpf_dev_tests_do_test

.PHONY: ebpf_tests
ebpf_tests:
	make -C ebpf_tests

.PHONY: ebpf_prog_tests
ebpf_prog_tests:
	make -C ebpf_prog_tests

.PHONY: ebpf_map_tests
ebpf_map_tests:
	make -C ebpf_map_tests

.PHONY: ebpf_dev_tests
ebpf_dev_tests:
	make -C ebpf_dev_tests 

clean_ebpf_tests:
	make -C ebpf_tests clean

clean_ebpf_prog_tests:
	make -C ebpf_prog_tests clean

clean_ebpf_map_tests:
	make -C ebpf_map_tests clean

clean_ebpf_dev_tests:
	make -C ebpf_dev_tests clean

ebpf_tests_do_test:
	make -C ebpf_tests do_test

ebpf_prog_tests_do_test:
	make -C ebpf_prog_tests do_test

ebpf_map_tests_do_test:
	make -C ebpf_map_tests do_test

ebpf_dev_tests_do_test:
	make -C ebpf_dev_tests do_test

gtest:
	make -C googletest/googletest/make gtest_main.a

clean_gtest:
	make -C googletest/googletest/make clean
