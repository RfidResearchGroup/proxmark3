# Hide full compilation line:
ifneq ($(V),1)
  Q?=@
endif
# To see full command lines, use make V=1

CC = gcc
CFLAGS = -std=c99 -Wall -O3 -I.
LDFLAGS = -std=c99 -Wall
SRC := $(wildcard *.c)
OBJ := $(SRC:.c=.o)
DEP := $(SRC:.c=.d)
PROG := nonce2key

all: $(PROG)

$(PROG): $(OBJ)
	$(info [=] LD $@)
	$(Q)$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

clean:
	$(Q)$(RM) $(DEP) $(OBJ) $(PROG)

ifneq ($(filter clean,$(MAKECMDGOALS)),clean)
-include $(DEP)
endif

%.d: %.c
	$(info [-] GEN $@)
	$(Q)$(CC) -MM $(CFLAGS) $< | sed 's/\($*\)\.o[ :]*/\1.o $@ : /g' > $@

%.o: %.c
	$(info [-] CC $<)
	$(Q)$(CC) -c $(CFLAGS) $(CPPFLAGS) -o $@ $<
