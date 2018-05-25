CFLAGS = \
	-I ../sys \
	-I ../tools/libgbpf/include \
	-L ../tools/libgbpf/lib \
	-Wall

all: $(platform)_map_benchmark
clean: $(platform)_clean

Linux_map_benchmark: map_benchmark.c
	$(CC) $(CFLAGS) -o map_benchmark map_benchmark.c -lgbpf
	$(CC) $(CFLAGS) -Dnative_bpf -o map_benchmark_native map_benchmark.c -lgbpf

FreeBSD_map_benchmark: map_benchmark.c
	$(CC) $(CFLAGS) -o map_benchmark map_benchmark.c -lgbpf

Darwin_map_benchmark:

Linux_clean:
	- rm -f map_benchmark map_benchmark_native

FreeBSD_clean:
	- rm -f map_benchmark

Darwin_clean:
