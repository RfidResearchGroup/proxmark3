#-----------------------------------------------------------------------------
# This code is licensed to you under the terms of the GNU GPL, version 2 or,
# at your option, any later version. See the LICENSE.txt file for the text of
# the license.
#-----------------------------------------------------------------------------

CC=gcc
CXX=g++
#COMMON_FLAGS = -m32

OBJDIR = obj

LDLIBS = -lreadline -lpthread
CFLAGS = -std=gnu99 -Wall -Wno-unused-function $(COMMON_FLAGS) -g -O3
ifeq ($(platform),Darwin)
	LDLIBS += -lusb-1.0
else
	LDLIBS += -lusb
endif

LDFLAGS = $(COMMON_FLAGS)
CXXFLAGS =

RM = rm -f
BINS = flasher
CLEAN = flasher flasher.exe $(OBJDIR)/*.o *.o

all: $(BINS)

flasher: $(OBJDIR)/flash.o $(OBJDIR)/flasher.o $(OBJDIR)/proxusb.o
	$(CXX) $(CXXFLAGS) $^ $(LDLIBS) -o $@

$(OBJDIR)/%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	$(RM) $(CLEAN)

# must be run as root
install_kext: Info.plist
	mkdir -p /System/Library/Extensions/Proxmark3.kext/Contents
	cp Info.plist /System/Library/Extensions/Proxmark3.kext/Contents
	chown -R root:wheel /System/Library/Extensions/Proxmark3.kext
	chmod 755 /System/Library/Extensions/Proxmark3.kext /System/Library/Extensions/Proxmark3.kext/Contents
	chmod 644 /System/Library/Extensions/Proxmark3.kext/Contents/Info.plist
	rm -rf /System/Library/Caches/com.apple.kext.caches
	touch /System/Library/Extensions
	@echo "*** You may need to reboot for the kext to take effect."

.PHONY: all clean
