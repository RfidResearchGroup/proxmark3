CFLAGS?=-Wall
LIBS=-lpthread
VPATH=../common
INC=-I ../common

all: ht2crack4.c hitagcrypto.o ht2crackutils.o
	$(CC) $(CFLAGS) $(INC) -o ht2crack4 $< hitagcrypto.o ht2crackutils.o $(LIBS)

hitagcrypto.o: hitagcrypto.c hitagcrypto.h
	$(CC) $(CFLAGS) -c $<

ht2crackutils.o: ht2crackutils.c ht2crackutils.h
	$(CC) $(CFLAGS) -c $<

clean:
	rm -rf *.o ht2crack4

fresh: clean all
