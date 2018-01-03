platdir = ../../$(platform)/ebpf/user

gtestobjs = \
	$(gtestpath)/googletest/make/gtest_main.o \
	$(gtestpath)/googletest/make/gtest-all.o

libebpf = ../../libebpf.a

CXXFLAGS = \
	-O0 \
	-I ../../sys \
	-I $(platdir) \
	-I $(gtestpath)/googletest/include \

prog_tests = \
	prog_load_test
	
all: $(prog_tests)

prog_load_test: prog_load_test.cpp
	$(CXX) $(CXXFLAGS) -o $@ prog_load_test.cpp $(gtestobjs) $(libebpf) -lpthread -coverage

do_test:
	./prog_load_test

clean:
	rm -f $(prog_tests) *.gcda *.gcno
