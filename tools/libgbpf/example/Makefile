CFLAGS= \
	-O3 \
	-I ../../../sys \
	-I ../include

all: printer test.o

printer: printer.c
	$(CC) -o $@ $(CFLAGS) printer.c ../lib/libgbpf.a -lelf

test.o: test.c
	/usr/local/bin/clang -target bpf $(CFLAGS) -c test.c

clean:
	rm -f printer test.o
