CFLAGS?=-Wall
# Linux libs
LIBS=-pthread -D_GNU_SOURCE
# Mac libs
# LIBS=
VPATH=../common
INC=-I ../common

all: ht2crack2buildtable.c ht2crack2search.c ht2crack2gentest.c hitagcrypto.o ht2crackutils.o
	$(CC) $(CFLAGS) $(INC) -o ht2crack2buildtable ht2crack2buildtable.c hitagcrypto.o ht2crackutils.o $(LIBS)
	$(CC) $(CFLAGS) $(INC) -o ht2crack2search ht2crack2search.c hitagcrypto.o ht2crackutils.o $(LIBS)
	$(CC) $(CFLAGS) $(INC) -o ht2crack2gentest ht2crack2gentest.c hitagcrypto.o ht2crackutils.o $(LIBS)

ht2crackutils.o: ht2crackutils.c ht2crackutils.h
	$(CC) $(CFLAGS) -c $<

hitagcrypto.o: hitagcrypto.c hitagcrypto.h
	$(CC) $(CFLAGS) -c $<

clean:
	rm -rf *.o ht2crack2buildtable ht2crack2search ht2crack2gentest

fresh: clean all
