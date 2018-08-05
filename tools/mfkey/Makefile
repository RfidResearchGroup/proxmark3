CC = gcc
LD = gcc
CFLAGS +=  -std=c99 -march=native -Wall -Winline -O3
LDFLAGS +=

OBJS = crapto1.o crypto1.o
HEADERS = crapto1.h
EXES = mfkey64 mfkey32 mfkey32v2
WINEXE = $(patsubst %, %.exe, $(EXES))
	
all: $(OBJS) $(EXES)

%.o : %.c
	$(CC) $(CFLAGS) -c -o $@ $<

% : %.c
	$(LD) $(CFLAGS) -o $@ $(OBJS) $<

clean: 
	rm -f $(OBJS) $(EXES) $(WINEXE)

