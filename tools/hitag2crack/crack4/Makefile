CFLAGS?=-Wall
LIBS=-lpthread
VPATH=../common
INC=-I ../common

all: ht2crack4.c HardwareProfile.h rfidler.h util.h utilpart.o hitagcrypto.o ht2crackutils.o
	$(CC) $(CFLAGS) $(INC) -o ht2crack4 $< utilpart.o hitagcrypto.o ht2crackutils.o $(LIBS)

utilpart.o: utilpart.c util.h
	$(CC) $(CFLAGS) -c $<

hitagcrypto.o: hitagcrypto.c hitagcrypto.h
	$(CC) $(CFLAGS) -c $<

ht2crackutils.o: ht2crackutils.c ht2crackutils.h
	$(CC) $(CFLAGS) -c $<

clean:
	rm -rf *.o ht2crack4

fresh: clean all
