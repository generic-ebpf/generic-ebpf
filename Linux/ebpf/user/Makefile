TOP_DIR:=../../../sys
SRC_DIR:=$(TOP_DIR)/dev/ebpf

ebpf-objs += $(SRC_DIR)/ebpf_vm.o
ebpf-objs += $(SRC_DIR)/ebpf_loader.o
ebpf-objs += $(SRC_DIR)/ebpf_verifer.o
ebpf-objs += $(SRC_DIR)/ebpf_map.o
ebpf-objs += $(SRC_DIR)/ebpf_prog.o
ebpf-objs += $(SRC_DIR)/ebpf_map_array.o
ebpf-objs += $(SRC_DIR)/tommyds/tommy.o
ebpf-objs += $(SRC_DIR)/ebpf_map_tommyhashtbl.o
ebpf-objs += ./ebpf_linux_user.o

ifeq ($(shell arch), x86_64)
	ebpf-objs += $(TOP_DIR)/amd64/amd64/ebpf_jit_x86_64.o
endif

CFLAGS += \
	-Ofast \
	-I $(SRC_DIR) \
	-I $(TOP_DIR) \
	-I $(CURDIR) \
	-Wall \
	-std=gnu11 -Wno-declaration-after-statement

LIBS = \
	-lpthread

ifeq ($(COVERAGE), 1)
	CFLAGS += -fprofile-arcs -ftest-coverage
endif

all: libebpf.a

libebpf.a: $(ebpf-objs)
	ar rc $@ $^

clean:
	rm -f libebpf.a *.o $(SRC_DIR)/*.o
