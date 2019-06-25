# Hide full compilation line:
ifneq ($(V),1)
  Q?=@
endif
# To see full command lines, use make V=1

VPATH = ../../common ../../common/crapto1 ../../client
CC = gcc
LD = gcc
CFLAGS += -std=c99 -D_ISOC99_SOURCE -I../../include -I../../common -I../../client -Wall -O3
LDFLAGS +=

OBJS = crypto1.o crapto1.o parity.o util_posix.o bucketsort.o
EXES = mfkey32 mfkey32v2 mfkey64

all: $(OBJS) $(EXES)

%.o : %.c
	$(info [-] CC $<)
	$(Q)$(CC) $(CFLAGS) -c -o $@ $<

% : %.c $(OBJS)
	$(info [=] LD $@)
	$(Q)$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJS) $<

clean:
	$(Q)rm -f $(OBJS) $(EXES)
