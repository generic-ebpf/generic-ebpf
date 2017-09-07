TOP_DIR:=../../sys
SRC_DIR:=$(TOP_DIR)/dev/ebpf

ebpf-objs += $(TOP_DIR)/dev/ebpf/ebpf_vm.o
ebpf-objs += $(TOP_DIR)/dev/ebpf/ebpf_loader.o
ebpf-objs += $(TOP_DIR)/dev/ebpf/ebpf_verifer.o
ebpf-objs += ./ebpf_osx_user.o

ifeq ($(shell arch), x86_64)
	ebpf-objs += $(TOP_DIR)/amd64/amd64/ebpf_jit_x86_64.o
endif

CFLAGS += \
	-I $(SRC_DIR) \
	-I $(TOP_DIR) \
	-I $(CURDIR) \
	-D user \
	-Wall \
	-g \
	-std=gnu11 -Wno-declaration-after-statement \

all: libebpf.a

libebpf.a: $(ebpf-objs)
	ar rc $@ $^

clean:
	rm libebpf.a $(SRC_DIR)/*.o ebpf_osx_user.o
