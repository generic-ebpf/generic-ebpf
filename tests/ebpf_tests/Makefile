test: test.c
	$(CC) -o $@ -I ../../sys test.c ../../libebpf.a

do_test:
	nosetests

clean:
	rm -f test
