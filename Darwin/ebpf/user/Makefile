TOP_DIR:=../../../sys
SRC_DIR:=$(TOP_DIR)/dev/ebpf

ebpf-objs += $(SRC_DIR)/ebpf_vm.o
ebpf-objs += $(SRC_DIR)/ebpf_loader.o
ebpf-objs += $(SRC_DIR)/ebpf_verifer.o
ebpf-objs += $(SRC_DIR)/ebpf_map.o
ebpf-objs += $(SRC_DIR)/ebpf_obj.o
ebpf-objs += $(SRC_DIR)/ebpf_map_array.o
ebpf-objs += ./ebpf_osx_user.o

ARCH:=$(shell arch)
ifeq ($(ARCH), i386)
	ebpf-objs += $(TOP_DIR)/amd64/amd64/ebpf_jit_x86_64.o
endif

CFLAGS += \
	-Ofast \
	-I $(SRC_DIR) \
	-I $(TOP_DIR) \
	-I $(CURDIR) \
	-Wall \
	-D user \
	-g \
	-std=gnu11 -Wno-declaration-after-statement \

ifeq ($(COVERAGE), 1)
	CFLAGS += -fprofile-arcs -ftest-coverage
endif

all: libebpf.a

libebpf.a: $(ebpf-objs)
	ar rc $@ $^

clean:
	rm -f libebpf.a $(ebpf-objs)
