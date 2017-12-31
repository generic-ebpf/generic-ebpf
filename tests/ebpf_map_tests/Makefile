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
	map_create_test \
	map_lookup_test \
	map_update_test \
	map_delete_test \
	map_get_next_key_test \
	array_map_delete_test \
	array_map_get_next_key_test \
	array_map_lookup_test \
	array_map_update_test

all: $(map_tests)

map_create_test: map_create_test.cpp
	$(CXX) $(CXXFLAGS) -o $@ map_create_test.cpp $(gtestobjs) $(libebpf) -lpthread -coverage

map_lookup_test: map_lookup_test.cpp
	$(CXX) $(CXXFLAGS) -o $@ map_lookup_test.cpp $(gtestobjs) $(libebpf) -lpthread -coverage

map_update_test: map_update_test.cpp
	$(CXX) $(CXXFLAGS) -o $@ map_update_test.cpp $(gtestobjs) $(libebpf) -lpthread -coverage

map_delete_test: map_delete_test.cpp
	$(CXX) $(CXXFLAGS) -o $@ map_delete_test.cpp $(gtestobjs) $(libebpf) -lpthread -coverage

map_get_next_key_test: map_get_next_key_test.cpp
	$(CXX) $(CXXFLAGS) -o $@ map_get_next_key_test.cpp $(gtestobjs) $(libebpf) -lpthread -coverage

array_map_delete_test: array_map_delete_test.cpp
	$(CXX) $(CXXFLAGS) -o $@ array_map_delete_test.cpp $(gtestobjs) $(libebpf) -lpthread -coverage

array_map_get_next_key_test: array_map_get_next_key_test.cpp
	$(CXX) $(CXXFLAGS) -o $@ array_map_get_next_key_test.cpp $(gtestobjs) $(libebpf) -lpthread -coverage

array_map_lookup_test: array_map_lookup_test.cpp
	$(CXX) $(CXXFLAGS) -o $@ array_map_lookup_test.cpp $(gtestobjs) $(libebpf) -lpthread -coverage

array_map_update_test: array_map_update_test.cpp
	$(CXX) $(CXXFLAGS) -o $@ array_map_update_test.cpp $(gtestobjs) $(libebpf) -lpthread -coverage

do_test:
	./map_create_test
	./map_lookup_test
	./map_update_test
	./map_delete_test
	./map_get_next_key_test
	./array_map_delete_test
	./array_map_get_next_key_test
	./array_map_lookup_test
	./array_map_update_test

clean:
	rm -f $(map_tests) *.gcda *.gcno
