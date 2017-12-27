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

prog_tests = \
	prog_load_test
	
map_tests = \
	map_create_test map_lookup_test map_update_test map_delete_test map_get_next_key_test

all: $(prog_tests) $(map_tests)

prog_load_test: prog_load_test.cpp
	$(CXX) $(CXXFLAGS) -o $@ prog_load_test.cpp $(gtestobjs) $(libebpf) -lpthread -coverage

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

do_test:
	./prog_load_test
	./map_create_test
	./map_lookup_test
	./map_update_test
	./map_delete_test
	./map_get_next_key_test

clean:
	rm -f $(prog_tests) $(map_tests) *.gcda *.gcno
