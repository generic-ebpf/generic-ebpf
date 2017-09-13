TOP_DIR:=../../sys
SRC_DIR:=$(TOP_DIR)/dev/ebpf
TEST_DIR:=../../test

ebpf-objs += $(SRC_DIR)/ebpf_vm.o
ebpf-objs += $(SRC_DIR)/ebpf_loader.o
ebpf-objs += $(SRC_DIR)/ebpf_verifer.o
ebpf-objs += ./ebpf_linux_user.o

ifeq ($(shell arch), x86_64)
	ebpf-objs += $(TOP_DIR)/amd64/amd64/ebpf_jit_x86_64.o
endif

CFLAGS += \
	-Ofast \
	-I $(SRC_DIR) \
	-I $(TOP_DIR) \
	-I $(CURDIR) \
	-D user \
	-Wall \
	-g \
	-std=gnu11 -Wno-declaration-after-statement \

all: libebpf.a test

libebpf.a: $(ebpf-objs)
	ar rc $@ $^

test: $(TEST_DIR)/test.o libebpf.a
	$(CC) $(CFLAGS) -o $(TEST_DIR)/$@ $^ -lm

clean:
	rm libebpf.a $(ebpf-objs) $(TEST_DIR)/test $(TEST_DIR)/test.o
