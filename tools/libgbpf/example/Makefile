CFLAGS= \
	-O3 \
	-I ../../../sys \
	-I ../include

all: printer test.o

printer: printer.c
	$(CC) -o $@ $(CFLAGS) printer.c ../lib/libgbpf.a -lelf

test.o: test.c
	clang -target bpf $(CFLAGS) -c test.c

clean:
	rm -f printer test.o
