CFLAGS = \
	-Ofast \
	-I ../../sys \
	-I ./include \
	-Wall \
	-Wextra \
	-Wno-unused-parameter \
	-g

CORE = \
	src/core/gbpf_elf_walker.o \
	src/core/gbpf_driver.o

DRIVERS = \
	src/drivers/gbpf_null_driver.o \
	src/drivers/ebpf_dev_driver.o

OBJS = $(CORE) $(DRIVERS)

all: lib example

.PHONY:lib
lib: $(OBJS)
	ar rc lib/libgbpf.a $(OBJS)

.PHONY:example
example:
	make -C example

clean:
	rm -f lib/*.a */**/*.o
	make -C example clean
