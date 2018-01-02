CC=clang
TOP_DIR:=../../../sys
SRC_DIR:=$(TOP_DIR)/dev/ebpf
TEST_DIR:=../../../tests/ebpf_tests

ebpf-objs += $(SRC_DIR)/ebpf_vm.o
ebpf-objs += $(SRC_DIR)/ebpf_loader.o
ebpf-objs += $(SRC_DIR)/ebpf_verifer.o
ebpf-objs += $(SRC_DIR)/ebpf_prog.o
ebpf-objs += $(SRC_DIR)/ebpf_map.o
ebpf-objs += $(SRC_DIR)/ebpf_map_array.o
ebpf-objs += ./ebpf_freebsd_user.o

ebpf-objs += $(SRC_DIR)/tommyds/tommy.o

ebpf-objs += $(SRC_DIR)/ebpf_map_tommyhashtbl.o

TARGET != uname -m
.if $(TARGET) == "amd64"
ebpf-objs += $(TOP_DIR)/amd64/amd64/ebpf_jit_x86_64.o
.endif

CFLAGS += \
	-Ofast \
	-I $(SRC_DIR) \
	-I $(TOP_DIR) \
	-I $(.CURDIR) \
	-Wall \
	-Duser \
	-g \
	-std=gnu11 -Wno-declaration-after-statement \

.if defined(COVERAGE) && $(COVERAGE) == 1
CFLAGS += -coverage
.endif

all: libebpf.a

libebpf.a: $(ebpf-objs)
	ar rc $@ $(ebpf-objs)

clean:
	rm -f libebpf.a $(ebpf-objs)
