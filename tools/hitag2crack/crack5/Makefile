CFLAGS?=-Wall
LIBS=-lpthread

all: ht2crack5.c utilpart.o ht2crack2utils.o hitagcrypto.o
	$(CC) $(CFLAGS) -O3 ht2crack5.c -o ht2crack5 utilpart.o ht2crack2utils.o hitagcrypto.o $(LIBS)

utilpart.o: util.h utilpart.c
	$(CC) $(CFLAGS) -c utilpart.c

hitagcrypto.o: hitagcrypto.h hitagcrypto.c
	$(CC) $(CFLAGS) -c hitagcrypto.c

ht2crack2utils.o: ht2crack2utils.h ht2crack2utils.c
	$(CC) $(CFLAGS) -c ht2crack2utils.c

clean:
	rm -f *.o ht2crack5
fresh: clean all
