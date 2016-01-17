CC = gcc
LD = gcc
CFLAGS = -Wall -Winline -O4
LDFLAGS =

OBJS = crapto1.o crypto1.o
HEADERS = crapto1.h
EXES = mfkey64 mfkey64.exe mfkey32 mfkey32.exe mfkey32v2 mfkey32v2.exe
LIBS =
	
all: $(OBJS) $(EXES) $(LIBS)

% : %.c $(OBJS)
	$(LD) $(CFLAGS) -o $@ $< $(OBJS) $(LDFLAGS)

clean: 
	rm -f $(OBJS) $(EXES) $(LIBS) 
