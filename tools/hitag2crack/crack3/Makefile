CFLAGS?=-Wall
LIBS=
VPATH=../common
INC=-I ../common

all: ht2crack3.c ht2test.c hitagcrypto.o utilpart.o
	$(CC) $(CFLAGS) $(INC) -o ht2crack3 $< hitagcrypto.o utilpart.o -lpthread $(LIBS)
	$(CC) $(CFLAGS) $(INC) -o ht2test ht2test.c hitagcrypto.o utilpart.o $(LIBS)

hitagcrypto.o: hitagcrypto.c hitagcrypto.h
	$(CC) $(CFLAGS) -c $<

utilpart.o: utilpart.c util.h
	$(CC) $(CFLAGS) -c $<

clean:
	rm -rf *.o ht2crack3 ht2test

fresh: clean all
