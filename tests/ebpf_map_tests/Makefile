platdir = ../../$(platform)/ebpf/user

gtestobjs = \
	$(gtestpath)/googletest/make/gtest-all.o \
	$(gtestpath)/googletest/make/gtest_main.o
deps = $(gtestobjs)

libebpf_path = ../../

CXXFLAGS = \
	-O0 \
	-g \
	-coverage \
	-L $(libebpf_path) \
	-I ../../sys \
	-I $(platdir) \
	-I $(gtestpath)/googletest/include \
	-Wno-unused-command-line-argument

map_tests = \
	map_create_test.o \
	map_lookup_test.o \
	map_update_test.o \
	map_delete_test.o \
	map_get_next_key_test.o \
	array_map_delete_test.o \
	array_map_get_next_key_test.o \
	array_map_lookup_test.o \
	array_map_update_test.o \
	percpu_array_map_delete_test.o \
	percpu_array_map_get_next_key_test.o \
	percpu_array_map_lookup_test.o \
	percpu_array_map_update_test.o \
	hashtable_map_delete_test.o \
	hashtable_map_get_next_key_test.o \
	hashtable_map_lookup_test.o \
	hashtable_map_update_test.o

all_tests: $(map_tests)
	$(CXX) $(CXXFLAGS) -o all_tests $(map_tests) $(deps) -lpthread -lebpf

check:
	- LD_LIBRARY_PATH=$(libebpf_path) ./all_tests

clean:
	rm -f all_tests $(map_tests) *.gcda *.gcno *.core
