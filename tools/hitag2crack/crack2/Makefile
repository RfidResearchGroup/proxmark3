WARN=-Wall
INCLUDE=-I../include
CFLAGS=-c $(WARN) $(INCLUDE)
# Linux libs
LIBS=-pthread -D_GNU_SOURCE
# Mac libs
# LIBS=

all: ht2crack2buildtable.c ht2crack2search.c ht2crack2gentest.c hitagcrypto.o utilpart.o ht2crack2utils.o
	cc $(WARN) -o ht2crack2buildtable ht2crack2buildtable.c hitagcrypto.o ht2crack2utils.o $(LIBS)
	cc $(WARN) -o ht2crack2search ht2crack2search.c hitagcrypto.o utilpart.o ht2crack2utils.o $(LIBS)
	cc $(WARN) -o ht2crack2gentest ht2crack2gentest.c hitagcrypto.o utilpart.o ht2crack2utils.o $(LIBS)

ht2crack2utils.o: ht2crack2utils.c ht2crack2utils.h
	cc $(CFLAGS) ht2crack2utils.c

hitagcrypto.o: hitagcrypto.c hitagcrypto.h
	cc $(CFLAGS) hitagcrypto.c

utilpart.o: utilpart.c util.h
	cc $(CFLAGS) utilpart.c

clean:
	rm -rf *.o ht2crack2buildtable ht2crack2search ht2crack2gentest

fresh: clean all
