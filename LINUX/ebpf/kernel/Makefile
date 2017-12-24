TOP_DIR:=../../../sys
SRC_DIR:=$(TOP_DIR)/dev/ebpf

ebpf-objs += $(SRC_DIR)/ebpf_vm.o
ebpf-objs += $(SRC_DIR)/ebpf_loader.o
ebpf-objs += $(SRC_DIR)/ebpf_verifer.o
ebpf-objs += $(SRC_DIR)/ebpf_obj.o
ebpf-objs += $(SRC_DIR)/ebpf_map.o
ebpf-objs += $(SRC_DIR)/ebpf_map_array.o
ebpf-objs += ./ebpf_linux.o

ifeq ($(shell arch), x86_64)
	ebpf-objs += $(TOP_DIR)/amd64/amd64/ebpf_jit_x86_64.o
endif

obj-m:=ebpf.o

LINUX_SRC:=/lib/modules/$(shell uname -r)/build

EXTRA_CFLAGS:= \
	-O3 \
	-I$(CURDIR)/$(TOP_DIR) \
	-I$(CURDIR) \
	-std=gnu11 -Wno-declaration-after-statement \

all:
	make -C $(LINUX_SRC) M=$(CURDIR) EXTRA_CFLAGS='$(EXTRA_CFLAGS)' modules

clean:
	make -C $(LINUX_SRC) M=$(CURDIR) clean
	rm -rf $(SRC_DIR)/modules.order $(SRC_DIR)/Module.symvers \
		$(SRC_DIR)/*.o $(SRC_DIR)/*.ko $(SRC_DIR)/.*.o.cmd $(SRC_DIR)/.*.ko.cmd \
		$(TOP_DIR)/amd64/amd64/*.o $(TOP_DIR)/amd64/amd64/.*.o.cmd
