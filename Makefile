.PHONY: all clean FreeBSD_all Linux_all Darwin_all FreeBSD_clean Linux_clean Darwin_clean \
	ebpf_user ebpf_kernel ebpf_dev tests clean_ebpf_user clean_ebpf_kernel clean_ebpf_dev do_test \
	clean_tests

# will be replaced by configure
export platform={{platform}}

all: $(platform)_all
clean: $(platform)_clean

FreeBSD_all: ebpf_user ebpf_kernel ebpf_dev tests
Linux_all: ebpf_user ebpf_kernel ebpf_dev tests
Darwin_all: ebpf_user tests

FreeBSD_clean: clean_ebpf_user clean_ebpf_kernel clean_ebpf_dev clean_tests
Linux_clean: clean_ebpf_user clean_ebpf_kernel clean_ebpf_dev clean_tests
Darwin_clean: clean_ebpf_user clean_tests

ebpf_user:
	make -C $(platform)/ebpf/user
	cp $(platform)/ebpf/user/libebpf.a .

ebpf_kernel:
	make -C $(platform)/ebpf/kernel
	cp $(platform)/ebpf/kernel/ebpf.ko .

ebpf_dev:
	make -C $(platform)/ebpf_dev
	cp $(platform)/ebpf_dev/ebpf-dev.ko .

tests:
	make -C tests

clean_ebpf_user:
	rm -f libebpf.a
	make -C $(platform)/ebpf/user clean

clean_ebpf_kernel:
	rm -f ebpf.ko
	make -C $(platform)/ebpf/kernel clean

clean_ebpf_dev:
	rm -f ebpf-dev.ko
	make -C $(platform)/ebpf_dev clean

do_test:
	make -C tests do_test

do_kernel_test:
	make -C tests do_kernel_test

clean_tests:
	make -C tests clean
