CFLAGS?=-Wall -O3
LIBS=-lpthread
VPATH=../common
INC=-I ../common

all: ht2crack5.c ht2crackutils.o hitagcrypto.o
	$(CC) $(CFLAGS) $(INC) -O3 $< -o ht2crack5 ht2crackutils.o hitagcrypto.o $(LIBS)

hitagcrypto.o: hitagcrypto.c hitagcrypto.h
	$(CC) $(CFLAGS) -c $<

ht2crackutils.o: ht2crackutils.c ht2crackutils.h
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f *.o ht2crack5
fresh: clean all
