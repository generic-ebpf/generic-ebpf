CFLAGS = \
	-I ../sys \
	-I ../tools/libgbpf/include \
	-L ../tools/libgbpf/lib

map_benchmark: map_benchmark.c
	$(CC) $(CFLAGS) -o $@ $^ -lgbpf

clean:
	- rm -f map_benchmark
