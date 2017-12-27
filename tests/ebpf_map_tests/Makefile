platdir = ../../$(platform)/ebpf/user

gtestobjs = \
	../googletest/googletest/src/gtest_main.cc \
	../gtest/gtest-all.cc

libebpf = ../../libebpf.a

CXXFLAGS = \
	-O0 \
	-I ../../sys \
	-I $(platdir) \
	-I ../googletest/googletest/include \

map_tests = \
	array_map_delete_test \
	array_map_get_next_key_test \
	array_map_lookup_test \
	array_map_update_test

all: $(prog_tests) $(map_tests)

array_map_delete_test: array_map_delete_test.cpp
	$(CXX) $(CXXFLAGS) -o $@ array_map_delete_test.cpp $(gtestobjs) $(libebpf) -lpthread -coverage

array_map_get_next_key_test: array_map_get_next_key_test.cpp
	$(CXX) $(CXXFLAGS) -o $@ array_map_get_next_key_test.cpp $(gtestobjs) $(libebpf) -lpthread -coverage

array_map_lookup_test: array_map_lookup_test.cpp
	$(CXX) $(CXXFLAGS) -o $@ array_map_lookup_test.cpp $(gtestobjs) $(libebpf) -lpthread -coverage

array_map_update_test: array_map_update_test.cpp
	$(CXX) $(CXXFLAGS) -o $@ array_map_update_test.cpp $(gtestobjs) $(libebpf) -lpthread -coverage

do_test:
	./array_map_delete_test
	./array_map_get_next_key_test
	./array_map_lookup_test
	./array_map_update_test

clean:
	rm -f $(prog_tests) $(map_tests) *.gcda *.gcno
