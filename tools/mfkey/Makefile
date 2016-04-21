CC = gcc
LD = gcc
CFLAGS =  -std=c99 -march=native -Wall -Winline -O3
LDFLAGS =

OBJS = crapto1.o crypto1.o
HEADERS = crapto1.h
EXES = mfkey64 mfkey32 mfkey32v2
WINEXE = mfkey64.exe mfkey32.exe mfkey32v2.exe
LIBS =
	
all: $(OBJS) $(EXES) $(LIBS)

% : %.c $(OBJS)
	$(LD) $(CFLAGS) -o $@ $< $(OBJS) $(LDFLAGS)

clean: 
	rm -f $(OBJS) $(EXES) $(LIBS) $(WINEXE)

