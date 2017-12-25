platform != uname
platdir = ../../$(platform)/ebpf/user

gtestobjs = \
	../googletest/googletest/src/gtest_main.cc \
	../gtest/gtest-all.cc

libebpf = ../../libebpf.a

CXXFLAGS = \
	-I ../../sys \
	-I $(platdir) \
	-I ../googletest/googletest/include \

map_tests = \
	create_test lookup_test update_test delete_test get_next_key_test

all: $(map_tests)

create_test: create_test.cpp
	$(CXX) $(CXXFLAGS) -o $@ create_test.cpp $(gtestobjs) $(libebpf) -lpthread -coverage

lookup_test: lookup_test.cpp
	$(CXX) $(CXXFLAGS) -o $@ lookup_test.cpp $(gtestobjs) $(libebpf) -lpthread -coverage

update_test: update_test.cpp
	$(CXX) $(CXXFLAGS) -o $@ update_test.cpp $(gtestobjs) $(libebpf) -lpthread -coverage

delete_test: delete_test.cpp
	$(CXX) $(CXXFLAGS) -o $@ delete_test.cpp $(gtestobjs) $(libebpf) -lpthread -coverage

get_next_key_test: get_next_key_test.cpp
	$(CXX) $(CXXFLAGS) -o $@ get_next_key_test.cpp $(gtestobjs) $(libebpf) -lpthread -coverage

do_test:
	./create_test
	./lookup_test
	./update_test
	./delete_test
	./get_next_key_test

clean:
	rm -f $(map_tests)
