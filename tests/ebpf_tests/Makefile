libebpf_path = ../../

test: test.c
	$(CC) -o $@ -O0 -L $(libebpf_path) -I ../../sys test.c -lm -lpthread -lebpf -coverage

do_test:
	LD_LIBRARY_PATH=$(libebpf_path) PYTHONPATH=../../tools nosetests

clean:
	rm -f test
