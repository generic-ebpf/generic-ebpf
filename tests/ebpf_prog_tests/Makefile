platdir = ../../$(platform)/ebpf/user

gtestobjs = \
	$(gtestpath)/googletest/make/gtest_main.o \
	$(gtestpath)/googletest/make/gtest-all.o
deps = $(gtestobjs)

libebpf_path=../../

CXXFLAGS = \
	-O0 \
	-L $(libebpf_path) \
	-I ../../sys \
	-I $(platdir) \
	-I $(gtestpath)/googletest/include \
	-Wno-unused-command-line-argument

prog_tests = \
	prog_load_test.o

all_tests: $(prog_tests)
	$(CXX) $(CXXFLAGS) -o all_tests $(deps) -lpthread -lebpf

do_test:
	- LD_LIBRARY_PATH=$(libebpf_path) ./all_tests

clean:
	rm -f all_tests $(prog_tests) *.gcda *.gcno
