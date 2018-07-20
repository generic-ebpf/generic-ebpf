TOP_DIR:=../../sys
SRC_DIR:=$(TOP_DIR)/dev/ebpf_dev

ebpf-dev-objs += $(SRC_DIR)/ebpf_dev.o
ebpf-dev-objs += $(SRC_DIR)/ebpf_obj.o
ebpf-dev-objs += ./ebpf_dev_linux.o

obj-m:=ebpf-dev.o

LINUX_SRC:=/lib/modules/$(shell uname -r)/build

EXTRA_CFLAGS:= \
	-Ofast \
	-D_KERNEL \
	-I$(CURDIR)/$(TOP_DIR) \
	-I$(CURDIR) \
	-I$(CURDIR)/../ebpf/kernel \
	-Wall \
	-Wno-declaration-after-statement \
	-std=gnu99

EXTRA_SYMBOLS:= \
	$(CURDIR)/../ebpf/kernel/Module.symvers

all:
	make -C $(LINUX_SRC) M=$(CURDIR) EXTRA_CFLAGS='$(EXTRA_CFLAGS)' \
		KBUILD_EXTRA_SYMBOLS='$(EXTRA_SYMBOLS)' modules

install:
	install ebpf-dev.ko $(DESTDIR)

clean:
	make -C $(LINUX_SRC) M=$(CURDIR) clean
	rm -rf $(SRC_DIR)/modules.order $(SRC_DIR)/Module.symvers \
		$(SRC_DIR)/*.o $(SRC_DIR)/*.ko $(SRC_DIR)/.*.o.cmd $(SRC_DIR)/.*.ko.cmd \
		$(TOP_DIR)/amd64/amd64/*.o $(TOP_DIR)/amd64/amd64/.*.o.cmd
