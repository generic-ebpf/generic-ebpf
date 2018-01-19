all: example test.o

example: example.c ebpf_dev_loader.h
	$(CC) -DDEBUG -Wall -Wextra -o $@ -g -I ../../sys example.c -lelf

test.o: test.c
	clang -target bpf -Wall -Wextra -I ../../sys -O3 -c test.c

clean:
	rm -f test.o example *.core *.bin
