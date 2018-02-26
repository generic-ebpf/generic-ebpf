test: test.c
	$(CC) -o $@ -O0 -I ../../sys test.c ../../libebpf.a -lm -lpthread -coverage

do_test:
	PYTHONPATH=../../tools nosetests

clean:
	rm -f test
