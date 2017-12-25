platform != uname

all: user kernel tests

kernel:
	make -C $(platform)/ebpf/kernel
	make -C $(platform)/ebpf_dev
	cp $(platform)/ebpf/kernel/ebpf.ko .
	cp $(platform)/ebpf_dev/ebpf-dev.ko .

clean_kernel:
	rm -f ebpf.ko ebpf-dev.ko
	make -C $(platform)/ebpf/kernel clean
	make -C $(platform)/ebpf_dev clean

user:
	make -C $(platform)/ebpf/user
	cp $(platform)/ebpf/user/libebpf.a .

clean_user:
	rm -f libebpf.a
	make -C $(platform)/ebpf/user clean

ebpf_tests:
	make -C tests/ebpf_tests

map_tests:
	make -C tests/map_tests

tests: ebpf_tests map_tests

do_ebpf_tests:
	make -C tests/ebpf_tests do_test

do_map_tests:
	make -C tests/map_tests do_test

do_test: do_ebpf_tests do_map_tests

clean_ebpf_tests:
	make -C tests/ebpf_tests clean

clean_map_tests:
	make -C tests/map_tests clean

clean_tests: clean_ebpf_tests clean_map_tests

load-Linux:
	insmod ./ebpf.ko
	insmod ./ebpf-dev.ko

unload-Linux:
	rmmod ebpf_dev
	rmmod ebpf

load-FreeBSD:
	kldload ./ebpf.ko
	kldload ./ebpf-dev.ko

unload-FreeBSD:
	kldunload ebpf-dev.ko
	kldunload ebpf.ko

load: load-$(platform)
unload: unload-$(platform)

clean: clean_kernel clean_user clean_tests
