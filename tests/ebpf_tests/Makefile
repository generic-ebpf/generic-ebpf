test: test.c
	$(CC) -o $@ -O0 -I ../../sys test.c ../../libebpf.a -lm -coverage

do_test:
	nosetests

clean:
	rm -f test
