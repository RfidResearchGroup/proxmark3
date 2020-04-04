CFLAGS?=-Wall
LIBS=-lpthread

all: ht2crack4.c HardwareProfile.h rfidler.h util.h utilpart.o hitagcrypto.o ht2crack2utils.o
	$(CC) $(CFLAGS) -o ht2crack4 ht2crack4.c utilpart.o hitagcrypto.o ht2crack2utils.o $(LIBS)

utilpart.o: utilpart.c util.h
	$(CC) $(CFLAGS) -c utilpart.c

hitagcrypto.o: hitagcrypto.c hitagcrypto.h
	$(CC) $(CFLAGS) -c hitagcrypto.c

ht2crack2utils.o: ht2crack2utils.c ht2crack2utils.h
	$(CC) $(CFLAGS) -c ht2crack2utils.c

clean:
	rm -rf *.o ht2crack4

fresh: clean all
