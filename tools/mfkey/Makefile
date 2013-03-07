CC = gcc
LD = gcc
CFLAGS = -Wall -Winline -O4
LDFLAGS =

OBJS = crapto1.o crypto1.o
HEADERS = 
EXES = mfkey
LIBS =
	
all: $(OBJS) $(EXES) $(LIBS)

% : %.c $(OBJS)
	$(LD) $(CFLAGS) -o $@ $< $(OBJS) $(LDFLAGS)

clean: 
	rm -f $(OBJS) $(EXES) $(LIBS) 
