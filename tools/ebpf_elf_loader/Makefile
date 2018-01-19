CFLAGS = \
	-I ../../sys \
	-Wall \
	-Wextra \
	-g \

all: example test.o

example: example.c ebpf_elf_loader.c ebpf_dev_elf_loader.c
	$(CC) $(CFLAGS) -o $@ example.c ebpf_elf_loader.c ebpf_dev_elf_loader.c -lelf

test.o: test.c
	clang -target bpf -Wall -Wextra -I ../../sys -O3 -c test.c

clean:
	rm -f example test.o *.core *.bin
