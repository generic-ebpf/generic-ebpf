CFLAGS = \
	-I ../sys \
	-I ../tools/libgbpf/include \
	-L ../tools/libgbpf/lib \
	-Wall

map_benchmark: map_benchmark.c
	$(CC) $(CFLAGS) -o $@ map_benchmark.c -lgbpf

clean:
	- rm -f map_benchmark
