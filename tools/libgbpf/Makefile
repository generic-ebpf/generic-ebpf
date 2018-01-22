CFLAGS = \
	-Ofast \
	-fPIC \
	-I ../../sys \
	-I ./include \
	-Wall \
	-Wextra \
	-Wno-unused-parameter \
	-g

CORE = \
	src/core/ebpf_elf_walker.o \
	src/core/ebpf_driver.o

DRIVERS = \
	src/drivers/ebpf_null_driver.o \
	src/drivers/ebpf_dev_driver.o

OBJS = $(CORE) $(DRIVERS)

all: lib example

.PHONY:lib
lib: $(OBJS)
	ar r lib/libgbpf.a $(OBJS)

.PHONY:example
example:
	make -C example

clean:
	rm -f lib/*.so
