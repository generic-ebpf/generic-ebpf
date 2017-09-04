TOP_DIR:=../sys

ebpf-objs += $(TOP_DIR)/dev/ebpf/ebpf_vm.o
ebpf-objs += $(TOP_DIR)/dev/ebpf/ebpf_loader.o
ebpf-objs += $(TOP_DIR)/dev/ebpf/ebpf_verifer.o
ebpf-objs += ./ebpf_linux.o

ifeq ($(shell arch), x86_64)
	ebpf-objs += $(TOP_DIR)/amd64/amd64/ebpf_jit_x86_64.o
endif

obj-m:=ebpf.o

LINUX_SRC:=/lib/modules/$(shell uname -r)/build

EXTRA_CFLAGS:= \
	-O3 \
	-I$(CURDIR)/../sys/dev/ebpf \
	-I$(CURDIR)/../sys \
	-I$(CURDIR) \
	-I$(LINUX_SRC)/include \
	-std=gnu11 -Wno-declaration-after-statement \

all:
	make -C $(LINUX_SRC) M=$(CURDIR) CONFIG_NETMAP=m \
		EXTRA_CFLAGS='$(EXTRA_CFLAGS)' KBUILD_EXTRA_SYMBOLS=$(NSRC)/LINUX/Module.symvers modules

clean:
	make -C $(LINUX_SRC) M=$(CURDIR) clean
	rm -rf $(SRC_DIR)/modules.order $(SRC_DIR)/Module.symvers \
		$(SRC_DIR)/*.o $(SRC_DIR)/*.ko $(SRC_DIR)/.*.o.cmd $(SRC_DIR)/.*.ko.cmd
