CC=clang
TOP_DIR:=../../../sys
SRC_DIR:=$(TOP_DIR)/dev/ebpf
TEST_DIR:=../../../tests/ebpf_tests

ebpf-src += ./ebpf_freebsd_user.c
ebpf-src += $(SRC_DIR)/ebpf_vm.c
ebpf-src += $(SRC_DIR)/ebpf_loader.c
ebpf-src += $(SRC_DIR)/ebpf_verifer.c
ebpf-src += $(SRC_DIR)/ebpf_prog.c
ebpf-src += $(SRC_DIR)/tommyds/tommy.c
ebpf-src += $(SRC_DIR)/ebpf_map.c
ebpf-src += $(SRC_DIR)/ebpf_map_bad.c
ebpf-src += $(SRC_DIR)/ebpf_map_array.c
ebpf-src += $(SRC_DIR)/ebpf_map_hashtable.c

TARGET != uname -m
.if $(TARGET) == "amd64"
ebpf-src += $(TOP_DIR)/amd64/amd64/ebpf_jit_x86_64.c
.endif

ebpf-objs = $(ebpf-src:%.c=%.o)

CFLAGS += \
	-Ofast \
	-fPIC \
	-I $(SRC_DIR) \
	-I $(TOP_DIR) \
	-I $(.CURDIR) \
	-Wall \
	-Duser \
	-g \
	-std=gnu11 -Wno-declaration-after-statement \

LIBS = \
	-lpthread

.if defined(COVERAGE) && $(COVERAGE) == 1
CFLAGS += -coverage
.endif

all: libebpf.so

libebpf.so:
	$(CC) $(CFLAGS) -shared -o $@ $(ebpf-src)

clean:
	rm -f libebpf.so $(ebpf-objs)
