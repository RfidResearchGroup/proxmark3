CFLAGS?=-Wall
LIBS=-lpthread
VPATH=../common
INC=-I ../common

all: ht2crack5.c utilpart.o ht2crackutils.o hitagcrypto.o
	$(CC) $(CFLAGS) $(INC) -O3 $< -o ht2crack5 utilpart.o ht2crackutils.o hitagcrypto.o $(LIBS)

utilpart.o: utilpart.c util.h
	$(CC) $(CFLAGS) -c $<

hitagcrypto.o: hitagcrypto.c hitagcrypto.h
	$(CC) $(CFLAGS) -c $<

ht2crackutils.o: ht2crackutils.c ht2crackutils.h
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f *.o ht2crack5
fresh: clean all
