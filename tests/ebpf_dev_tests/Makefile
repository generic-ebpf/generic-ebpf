platdir = ../../$(platform)/ebpf/user

gtestobjs = $(gtestpath)/googletest/make/gtest-all.o \
	$(gtestpath)/googletest/make/gtest_main.o

libebpf = ../../libebpf.a

CXXFLAGS = \
	-O0 \
	-I ../../sys \
	-I $(platdir) \
	-I $(gtestpath)/googletest/include \

map_tests = \
	ebpf_dev_map_create_test \
	ebpf_dev_map_update_elem_test \
	ebpf_dev_map_lookup_elem_test \
	ebpf_dev_map_delete_elem_test \
	ebpf_dev_map_get_next_key_test

prog_tests = \
	ebpf_dev_prog_load_test \
	ebpf_dev_run_test_test

all: $(map_tests) $(prog_tests)

ebpf_dev_map_create_test: ebpf_dev_map_create_test.cpp
	$(CXX) $(CXXFLAGS) -o $@ ebpf_dev_map_create_test.cpp $(gtestobjs) $(libebpf) -lpthread -coverage

ebpf_dev_map_update_elem_test: ebpf_dev_map_update_elem_test.cpp
	$(CXX) $(CXXFLAGS) -o $@ ebpf_dev_map_update_elem_test.cpp $(gtestobjs) $(libebpf) -lpthread -coverage

ebpf_dev_map_lookup_elem_test: ebpf_dev_map_lookup_elem_test.cpp
	$(CXX) $(CXXFLAGS) -o $@ ebpf_dev_map_lookup_elem_test.cpp $(gtestobjs) $(libebpf) -lpthread -coverage

ebpf_dev_map_delete_elem_test: ebpf_dev_map_delete_elem_test.cpp
	$(CXX) $(CXXFLAGS) -o $@ ebpf_dev_map_delete_elem_test.cpp $(gtestobjs) $(libebpf) -lpthread -coverage

ebpf_dev_map_get_next_key_test: ebpf_dev_map_get_next_key_test.cpp
	$(CXX) $(CXXFLAGS) -o $@ ebpf_dev_map_get_next_key_test.cpp $(gtestobjs) $(libebpf) -lpthread -coverage

ebpf_dev_prog_load_test: ebpf_dev_prog_load_test.cpp
	$(CXX) $(CXXFLAGS) -o $@ ebpf_dev_prog_load_test.cpp $(gtestobjs) $(libebpf) -lpthread -coverage

ebpf_dev_run_test_test: ebpf_dev_run_test_test.cpp
	$(CXX) $(CXXFLAGS) -o $@ ebpf_dev_run_test_test.cpp $(gtestobjs) $(libebpf) -lpthread -coverage

do_test:
	./ebpf_dev_map_create_test
	./ebpf_dev_map_update_elem_test
	./ebpf_dev_map_lookup_elem_test
	./ebpf_dev_map_delete_elem_test
	./ebpf_dev_map_get_next_key_test
	./ebpf_dev_prog_load_test
	./ebpf_dev_run_test_test

clean:
	rm -f $(map_tests) $(prog_tests) *.gcda *.gcno
