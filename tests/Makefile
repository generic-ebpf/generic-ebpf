all: $(platform)_all
clean: $(platform)_clean
check: $(platform)_check
check_kernel: $(platform)_check_kernel

FreeBSD_all: ebpf_tests ebpf_prog_tests ebpf_map_tests ebpf_dev_tests
Linux_all: ebpf_tests ebpf_prog_tests ebpf_map_tests ebpf_dev_tests
Darwin_all: ebpf_tests ebpf_prog_tests ebpf_map_tests

FreeBSD_clean: clean_gtest clean_ebpf_tests clean_ebpf_prog_tests clean_ebpf_map_tests clean_ebpf_dev_tests
Linux_clean: clean_gtest clean_ebpf_tests clean_ebpf_prog_tests clean_ebpf_map_tests clean_ebpf_dev_tests
Darwin_clean: clean_gtest clean_ebpf_tests clean_ebpf_prog_tests clean_ebpf_map_tests

FreeBSD_check: ebpf_tests_check ebpf_prog_tests_check ebpf_map_tests_check
Linux_check: ebpf_tests_check ebpf_prog_tests_check ebpf_map_tests_check
Darwin_check: ebpf_tests_check ebpf_prog_tests_check ebpf_map_tests_check

FreeBSD_check_kernel: ebpf_dev_tests_check
Linux_check_kernel: ebpf_dev_tests_check

.PHONY: ebpf_tests
ebpf_tests:
	make -C ebpf_tests

.PHONY: ebpf_prog_tests
ebpf_prog_tests: gtest
	make -C ebpf_prog_tests

.PHONY: ebpf_map_tests
ebpf_map_tests: gtest
	make -C ebpf_map_tests

.PHONY: ebpf_dev_tests
ebpf_dev_tests: gtest
	make -C ebpf_dev_tests 

clean_ebpf_tests:
	make -C ebpf_tests clean

clean_ebpf_prog_tests:
	make -C ebpf_prog_tests clean

clean_ebpf_map_tests:
	make -C ebpf_map_tests clean

clean_ebpf_dev_tests:
	make -C ebpf_dev_tests clean

ebpf_tests_check:
	make -C ebpf_tests check

ebpf_prog_tests_check:
	make -C ebpf_prog_tests check

ebpf_map_tests_check:
	make -C ebpf_map_tests check

ebpf_dev_tests_check:
	make -C ebpf_dev_tests check

.PHONY: gtest
gtest:
	make -C $(gtestpath)/googletest/make gtest_main.a

clean_gtest:
	make -C $(gtestpath)/googletest/make clean
