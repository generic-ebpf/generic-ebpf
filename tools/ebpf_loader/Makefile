CFLAGS = \
	-DDEBUG \
	-Ofast \
	-fPIC \
	-I ../../sys \
	-Wall \
	-Wextra \
	-Wno-unused-parameter \
	-g

all: ebpf_loader ebpf_iface ebpf_dev_iface

ebpf_loader: ebpf_loader.c
	$(CC) $(CFLAGS) -shared ebpf_loader.c -o libebpf_loader.so -lelf

ebpf_iface: ebpf_iface.c
	$(CC) $(CFLAGS) -shared ebpf_iface.c -o libebpf_iface.so

ebpf_dev_iface:
	$(CC) $(CFLAGS) -shared ebpf_dev_iface.c -o libebpf_dev_iface.so

clean:
	rm -f *.o *.core *.so
