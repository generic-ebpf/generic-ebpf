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

tests:
	make -C $(platform)/ebpf/user test

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

clean: clean_kernel clean_user
