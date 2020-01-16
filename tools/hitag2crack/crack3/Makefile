WARN=-Wall
INCLUDE=-I../include
CFLAGS=-c $(WARN) $(INCLUDE)
LIBS=

all: ht2crack3.c ht2test.c hitagcrypto.o utilpart.o
	cc $(WARN) -o ht2crack3 ht2crack3.c hitagcrypto.o utilpart.o -lpthread $(LIBS)
	cc $(WARN) -o ht2test ht2test.c hitagcrypto.o utilpart.o $(LIBS)

hitagcrypto.o: hitagcrypto.c hitagcrypto.h
	cc $(CFLAGS) hitagcrypto.c

utilpart.o: utilpart.c util.h
	cc $(CFLAGS) utilpart.c

clean:
	rm -rf *.o ht2crack3 ht2test

fresh: clean all
