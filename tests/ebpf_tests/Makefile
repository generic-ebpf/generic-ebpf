test: test.c
	$(CC) -o $@ -I ../../sys test.c ../../libebpf.a -lm

do_test:
	nosetests

clean:
	rm -f test
