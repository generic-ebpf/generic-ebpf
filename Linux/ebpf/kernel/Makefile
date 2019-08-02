BASE:=	../../..
TOP_DIR:=	$(BASE)/sys
SRC_DIR:=	$(BASE)/sys/dev/ebpf

ebpf-objs+=	$(SRC_DIR)/ebpf_allocator.o
ebpf-objs+=	$(SRC_DIR)/ebpf_map.o
ebpf-objs+=	$(SRC_DIR)/ebpf_map_array.o
ebpf-objs+=	$(SRC_DIR)/ebpf_map_hashtable.o
ebpf-objs+=	$(SRC_DIR)/ebpf_obj.o
ebpf-objs+=	$(SRC_DIR)/ebpf_prog.o
ebpf-objs+=	$(SRC_DIR)/ebpf_prog.o
ebpf-objs+=	$(SRC_DIR)/ebpf_verifier.o
ebpf-objs+=	$(SRC_DIR)/ebpf_vm.o
ebpf-objs+=	./ebpf_linux.o

ifeq ($(shell arch), x86_64)
ebpf-objs+=	$(BASE)/sys/amd64/amd64/ebpf_jit_x86_64.o
endif

obj-m:=ebpf.o

LINUX_SRC:=/lib/modules/$(shell uname -r)/build

EXTRA_CFLAGS:= \
	-Ofast \
	-D_KERNEL \
	-I$(CURDIR)/$(TOP_DIR) \
	-I$(CURDIR) \
	-Wall \
	-Wno-declaration-after-statement \
	-std=gnu99

all:
	- rm -f $(ebpf-objs)
	make -C $(LINUX_SRC) M=$(CURDIR) EXTRA_CFLAGS='$(EXTRA_CFLAGS)' modules

install:
	install ebpf.ko $(DESTDIR)

clean:
	make -C $(LINUX_SRC) M=$(CURDIR) clean
	- rm -rf $(ebpf-objs)
