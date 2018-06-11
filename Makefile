# will be replaced by configure
export platform={{platform}}
export gtestpath=$(PWD)/extern/googletest

all: $(platform)_all
clean: $(platform)_clean

FreeBSD_all: ebpf_user ebpf_kernel ebpf_dev libgbpf benchmark tests
Linux_all: ebpf_user ebpf_kernel ebpf_dev libgbpf benchmark tests
Darwin_all: ebpf_user_darwin libgbpf tests

FreeBSD_clean: clean_ebpf_user clean_ebpf_kernel clean_ebpf_dev clean_tests clean_benchmark clean_libgbpf
Linux_clean: clean_ebpf_user clean_ebpf_kernel clean_ebpf_dev clean_tests clean_benchmark clean_libgbpf
Darwin_clean: clean_ebpf_user_darwin clean_tests clean_libgbpf

ebpf_user:
	make -C $(platform)/ebpf/user
	cp $(platform)/ebpf/user/libebpf.so .

ebpf_user_darwin:
	make -C $(platform)/ebpf/user
	cp $(platform)/ebpf/user/libebpf.dylib .

ebpf_kernel:
	make -C $(platform)/ebpf/kernel
	cp $(platform)/ebpf/kernel/ebpf.ko .

ebpf_dev:
	make -C $(platform)/ebpf_dev
	cp $(platform)/ebpf_dev/ebpf-dev.ko .

.PHONY: tests
tests:
	make -C tests

clean_ebpf_user:
	rm -f libebpf.so
	make -C $(platform)/ebpf/user clean

clean_ebpf_user_darwin:
	rm -f libebpf.dylib
	make -C $(platform)/ebpf/user clean

clean_ebpf_kernel:
	rm -f ebpf.ko
	make -C $(platform)/ebpf/kernel clean

clean_ebpf_dev:
	rm -f ebpf-dev.ko
	make -C $(platform)/ebpf_dev clean

check:
	make -C tests check

check_kernel:
	make -C tests check_kernel

clean_tests:
	make -C tests clean

libgbpf:
	make -C tools/libgbpf

clean_libgbpf:
	make -C tools/libgbpf clean

.PHONY: benchmark
benchmark:
	make -C benchmark

clean_benchmark:
	make -C benchmark clean

format:
	clang-format -i */**/*.{c,h,cpp}
