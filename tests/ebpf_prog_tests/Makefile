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
	
all: $(prog_tests)

prog_load_test: prog_load_test.cpp
	$(CXX) $(CXXFLAGS) -o $@ prog_load_test.cpp $(gtestobjs) $(libebpf) -lpthread -coverage

do_test:
	./prog_load_test

clean:
	rm -f $(prog_tests) *.gcda *.gcno
