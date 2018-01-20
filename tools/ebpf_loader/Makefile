CFLAGS = \
	-DDEBUG \
	-Ofast \
	-fPIC \
	-I ../../sys \
	-Wall \
	-Wextra \
	-Wno-unused-parameter \
	-g

all: ebpf_loader ebpf_driver ebpf_dev_driver

ebpf_loader: ebpf_loader.c
	$(CC) $(CFLAGS) -shared ebpf_loader.c -o libebpf_loader.so -lelf

ebpf_driver: ebpf_driver.c
	$(CC) $(CFLAGS) -shared ebpf_driver.c -o libebpf_driver.so

ebpf_dev_driver:
	$(CC) $(CFLAGS) -shared ebpf_dev_driver.c -o libebpf_dev_driver.so

clean:
	rm -f *.o *.core *.so
