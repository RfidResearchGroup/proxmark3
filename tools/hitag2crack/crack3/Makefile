CFLAGS?=-Wall -Werror -O3
LIBS=
VPATH=../common
INC=-I ../common

all: ht2crack3.c ht2test.c hitagcrypto.o ht2crackutils.o
	$(CC) $(CFLAGS) $(INC) -o ht2crack3 $< hitagcrypto.o ht2crackutils.o -lpthread $(LIBS)
	$(CC) $(CFLAGS) $(INC) -o ht2test ht2test.c hitagcrypto.o ht2crackutils.o $(LIBS)

ht2crackutils.o: ht2crackutils.c ht2crackutils.h
	$(CC) $(CFLAGS) -c $<

hitagcrypto.o: hitagcrypto.c hitagcrypto.h
	$(CC) $(CFLAGS) -c $<

clean:
	rm -rf *.o ht2crack3 ht2test

fresh: clean all
