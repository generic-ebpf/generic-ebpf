all: example test.o

example: example.c ebpf_dev_loader.h
	$(CC) -o $@ -g -I ../../sys example.c -lelf

test.o: test.c
	clang38 -target bpf -I ../../sys -O3 -c test.c

clean:
	rm -f test.o example *.core *.bin
