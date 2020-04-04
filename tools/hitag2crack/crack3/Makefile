CFLAGS?=-Wall
LIBS=

all: ht2crack3.c ht2test.c hitagcrypto.o utilpart.o
	$(CC) $(CFLAGS) -o ht2crack3 ht2crack3.c hitagcrypto.o utilpart.o -lpthread $(LIBS)
	$(CC) $(CFLAGS) -o ht2test ht2test.c hitagcrypto.o utilpart.o $(LIBS)

hitagcrypto.o: hitagcrypto.c hitagcrypto.h
	$(CC) $(CFLAGS) -c hitagcrypto.c

utilpart.o: utilpart.c util.h
	$(CC) $(CFLAGS) -c utilpart.c

clean:
	rm -rf *.o ht2crack3 ht2test

fresh: clean all
