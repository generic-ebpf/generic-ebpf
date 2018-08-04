TOP_DIR:=../../../sys
SRC_DIR:=$(TOP_DIR)/dev/ebpf

ebpf-src += $(SRC_DIR)/ebpf_vm.c
ebpf-src += $(SRC_DIR)/ebpf_loader.c
ebpf-src += $(SRC_DIR)/ebpf_verifer.c
ebpf-src += $(SRC_DIR)/ebpf_map.c
ebpf-src += $(SRC_DIR)/ebpf_prog.c
ebpf-src += $(SRC_DIR)/ebpf_map_bad.c
ebpf-src += $(SRC_DIR)/ebpf_map_array.c
ebpf-src += ./ebpf_linux_user.c

ifeq ($(shell arch), x86_64)
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
	-Wno-declaration-after-statement \
	-std=gnu99

LIBS = \
	-lpthread

ifeq ($(COVERAGE), 1)
	CFLAGS += -coverage
endif

all: libebpf.so

libebpf.so:
	$(CC) $(CFLAGS) -shared -o $@ $(ebpf-src)

install:
	cp libebpf.so ../../../

clean:
	rm -f libebpf.so $(ebpf-objs)
