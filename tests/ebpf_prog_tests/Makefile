platdir = ../../$(platform)/ebpf/user

gtestobjs = \
	$(gtestpath)/googletest/make/gtest_main.o \
	$(gtestpath)/googletest/make/gtest-all.o
libebpf = ../../libebpf.a
deps = $(gtestobjs) $(libebpf)

CXXFLAGS = \
	-O0 \
	-I ../../sys \
	-I $(platdir) \
	-I $(gtestpath)/googletest/include \

prog_tests = \
	prog_load_test.o

all_tests: $(prog_tests)
	$(CXX) $(CXXFLAGS) -o all_tests $(deps) -lpthread

do_test:
	- ./all_tests

clean:
	rm -f all_tests $(prog_tests) *.gcda *.gcno
