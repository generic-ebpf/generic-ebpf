CFLAGS = \
	-O3 \
	-I ../../../sys \
	-I ../include \
	-Wall

all: printer test.o

printer: printer.c
	$(CC) -o $@ $(CFLAGS) printer.c ../lib/libgbpf.a -lelf

EBPF_CFLAGS = \
	-O3 \
	-I ../../../sys \
	-I ../include \
	-target bpf \
	-c

test.o: test.c
	clang $(EBPF_CFLAGS) test.c

clean:
	rm -f printer test.o
