CC = gcc
LD = gcc
CFLAGS = -Wall -O4 -c
LDFLAGS =

OBJS = crypto1.o crapto1.o
HEADERS = crapto1.h
EXES = nonce2key

all: $(OBJS) $(EXES)

%.o : %.c
	$(CC) $(CFLAGS) -o $@ $<

% : %.c
	$(LD) $(LDFLAGS) -o $@ $(OBJS) $<

crypto1test: libnfc $(OBJS)
	$(LD) $(LDFLAGS) -o crypto1test crypto1test.c $(OBJS)
 
clean: 
	rm -f $(OBJS) $(EXES)
