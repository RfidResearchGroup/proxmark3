CFLAGS?=-Wall
# Linux libs
LIBS=-pthread -D_GNU_SOURCE
# Mac libs
# LIBS=

all: ht2crack2buildtable.c ht2crack2search.c ht2crack2gentest.c hitagcrypto.o utilpart.o ht2crack2utils.o
	$(CC) $(CFLAGS) -o ht2crack2buildtable ht2crack2buildtable.c hitagcrypto.o ht2crack2utils.o $(LIBS)
	$(CC) $(CFLAGS) -o ht2crack2search ht2crack2search.c hitagcrypto.o utilpart.o ht2crack2utils.o $(LIBS)
	$(CC) $(CFLAGS) -o ht2crack2gentest ht2crack2gentest.c hitagcrypto.o utilpart.o ht2crack2utils.o $(LIBS)

ht2crack2utils.o: ht2crack2utils.c ht2crack2utils.h
	$(CC) $(CFLAGS) -c ht2crack2utils.c

hitagcrypto.o: hitagcrypto.c hitagcrypto.h
	$(CC) $(CFLAGS) -c hitagcrypto.c

utilpart.o: utilpart.c util.h
	$(CC) $(CFLAGS) -c utilpart.c

clean:
	rm -rf *.o ht2crack2buildtable ht2crack2search ht2crack2gentest

fresh: clean all
