platdir = ../../$(platform)/ebpf/user

gtestobjs = $(gtestpath)/googletest/make/gtest-all.o \
	$(gtestpath)/googletest/make/gtest_main.o
libebpf = ../../libebpf.a
deps = $(gtestobjs) $(libebpf)

CXXFLAGS = \
	-O0 \
	-I ../../sys \
	-I $(platdir) \
	-I $(gtestpath)/googletest/include \
	-coverage

map_tests = \
	ebpf_dev_map_create_test.o \
	ebpf_dev_map_update_elem_test.o \
	ebpf_dev_map_lookup_elem_test.o \
	ebpf_dev_map_delete_elem_test.o \
	ebpf_dev_map_get_next_key_test.o

prog_tests = \
	ebpf_dev_prog_load_test.o \
	ebpf_dev_run_test_test.o

all_tests: $(map_tests) $(prog_tests)
	$(CXX) $(CXXFLAGS) -o all_tests $(deps) -lpthread

do_test:
	- ./all_tests

clean:
	rm -f all_tests $(map_tests) $(prog_tests) *.gcda *.gcno
