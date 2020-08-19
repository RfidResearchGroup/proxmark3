CC = gcc
CXX = g++
LD = gcc
LXX = g++
CFLAGS = -W -Wall -O4
CXXFLAGS = -W -Wall -O4 -std=c++11
LDFLAGS = 
LXXFLAGS =  -lpthread 

OBJS = cryptolib.o util.o
HEADERS = cryptolib.h util.h
SRC = cryptolib.c util.c
EXES = cm sm sma sma_multi 
#EXES = cm sm sma sma_multi crf

all: $(OBJS) $(EXES)

%.o : %.c
	$(CC) $(CFLAGS) -c -o $@ $<

% : %.c $(OBJS)
	$(LD) $(CFLAGS) $(LDFLAGS) -o $@ $< $(OBJS)

% : %.cpp $(SRC)
	$(LXX) $(CXXFLAGS) -o $@ $< $(SRC) $(LXXFLAGS)

crf: crf.c $(OBJS)
	$(LD) $(CFLAGS) $(LDFLAGS) -o crf $< $(OBJS) -lnfc

clean:
	rm -f $(OBJS) $(EXES) crf
