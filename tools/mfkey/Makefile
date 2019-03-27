VPATH = ../../common ../../common/crapto1 ../../client
CC = gcc
LD = gcc
CFLAGS += -std=c99 -D_ISOC99_SOURCE -I../../include -I../../common -I../../client -Wall -O3
LDFLAGS +=

OBJS = crypto1.o crapto1.o parity.o util_posix.o bucketsort.o
EXES = mfkey32 mfkey32v2 mfkey64 
WINEXES = $(patsubst %, %.exe, $(EXES))

all: $(OBJS) $(EXES)

%.o : %.c
	$(CC) $(CFLAGS) -c -o $@ $<

% : %.c $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJS) $<

clean:
	rm -f $(OBJS) $(EXES) $(WINEXES)
