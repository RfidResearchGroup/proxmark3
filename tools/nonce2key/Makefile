CC = gcc
CFLAGS = -std=c99 -Wall -O3 -I.
LDFLAGS = -std=c99 -Wall
SRC := $(wildcard *.c)
OBJ := $(SRC:.c=.o)
DEP := $(SRC:.c=.d)
PROG := nonce2key

all: $(PROG)

$(PROG): $(OBJ)
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

clean:
	@$(RM) $(DEP) $(OBJ) $(PROG)

ifneq ($(filter clean,$(MAKECMDGOALS)),clean)
-include $(DEP)
endif

%.d: %.c
	$(info GEN $@)
	@$(CC) -MM $(CFLAGS) $< | sed 's/\($*\)\.o[ :]*/\1.o $@ : /g' > $@
