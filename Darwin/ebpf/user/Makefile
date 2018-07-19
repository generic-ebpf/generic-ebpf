TOP_DIR:=../../../sys
SRC_DIR:=$(TOP_DIR)/dev/ebpf

ebpf-src += ./ebpf_osx_user.c
ebpf-src += $(SRC_DIR)/ebpf_vm.c
ebpf-src += $(SRC_DIR)/ebpf_loader.c
ebpf-src += $(SRC_DIR)/ebpf_verifer.c
ebpf-src += $(SRC_DIR)/ebpf_map.c
ebpf-src += $(SRC_DIR)/ebpf_prog.c
ebpf-src += $(SRC_DIR)/ebpf_allocator.c
ebpf-src += $(SRC_DIR)/ebpf_map_bad.c
ebpf-src += $(SRC_DIR)/ebpf_map_array.c
ebpf-src += $(SRC_DIR)/ebpf_map_hashtable.c

ARCH:=$(shell arch)
ifeq ($(ARCH), i386)
	ebpf-src += $(TOP_DIR)/amd64/amd64/ebpf_jit_x86_64.c
endif

ebpf-objs = $(ebpf-src:%.c=%.o)

CFLAGS += \
	-Ofast \
	-fPIC \
	-I $(SRC_DIR) \
	-I $(TOP_DIR) \
	-I $(CURDIR) \
	-Wall \
	-Duser \
	-Wno-declaration-after-statement \
	-std=c99

ifeq ($(COVERAGE), 1)
	CFLAGS += -coverage
endif

all: libebpf.dylib

libebpf.dylib:
	$(CC) $(CFLAGS) -shared -o $@ $(ebpf-src) -lpthread

clean:
	rm -f libebpf.dylib $(ebpf-objs)
