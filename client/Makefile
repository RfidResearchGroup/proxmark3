#-----------------------------------------------------------------------------
# This code is licensed to you under the terms of the GNU GPL, version 2 or,
# at your option, any later version. See the LICENSE.txt file for the text of
# the license.
#-----------------------------------------------------------------------------
include ../common/Makefile.common

CC=gcc
CXX=g++
#COMMON_FLAGS = -m32

VPATH = ../common
OBJDIR = obj

LDLIBS = -L/opt/local/lib -L/usr/local/lib -lusb -lreadline -lpthread
LDFLAGS = $(COMMON_FLAGS)
CFLAGS = -std=gnu99 -I. -I../include -I../common -I/opt/local/include -Wall -Wno-unused-function $(COMMON_FLAGS) -g -O3

ifneq (,$(findstring MINGW,$(platform)))
CXXFLAGS = -I$(QTDIR)/include -I$(QTDIR)/include/QtCore -I$(QTDIR)/include/QtGui
QTLDLIBS = -L$(QTDIR)/lib -lQtCore4 -lQtGui4
MOC = moc
else ifeq ($(platform),Darwin)
CXXFLAGS = -I/Library/Frameworks/QtGui.framework/Versions/Current/Headers -I/Library/Frameworks/QtCore.framework/Versions/Current/Headers
QTLDLIBS = -framework QtGui -framework QtCore
MOC = moc 
else
CXXFLAGS = $(shell pkg-config --cflags QtCore QtGui 2>/dev/null) -Wall -O3
QTLDLIBS = $(shell pkg-config --libs QtCore QtGui 2>/dev/null)
MOC = $(shell pkg-config --variable=moc_location QtCore)
endif


ifneq ($(QTLDLIBS),)
QTGUI = $(OBJDIR)/proxgui.o $(OBJDIR)/proxguiqt.o $(OBJDIR)/proxguiqt.moc.o
CFLAGS += -DHAVE_GUI
LINK.o = $(LINK.cpp)
else
QTGUI = guidummy.o
endif

CMDSRCS = \
			nonce2key/crapto1.c\
			nonce2key/crypto1.c\
			nonce2key/nonce2key.c\
			mifarehost.c\
			crc16.c \
			iso14443crc.c \
			iso15693tools.c \
			data.c \
			graph.c \
			ui.c \
			util.c \
			cmddata.c \
			cmdhf.c \
			cmdhf14a.c \
			cmdhf14b.c \
			cmdhf15.c \
			cmdhfepa.c \
			cmdhflegic.c \
			cmdhficlass.c \
			cmdhfmf.c \
			cmdhw.c \
			cmdlf.c \
			cmdlfem4x.c \
			cmdlfhid.c \
			cmdlfhitag.c \
			cmdlfti.c \
			cmdparser.c \
			cmdmain.c

CMDOBJS = $(CMDSRCS:%.c=$(OBJDIR)/%.o)

RM = rm -f
BINS = proxmark3 snooper cli flasher
CLEAN = cli cli.exe flasher flasher.exe proxmark3 proxmark3.exe snooper snooper.exe $(CMDOBJS) $(OBJDIR)/*.o *.o *.moc.cpp

all: $(BINS)

all-static: LDLIBS:=-static $(LDLIBS)
all-static: snooper cli flasher
	
proxmark3: LDLIBS+=$(QTLDLIBS)
proxmark3: $(OBJDIR)/proxmark3.o $(CMDOBJS) $(OBJDIR)/proxusb.o $(QTGUI)
	$(CXX) $(CXXFLAGS) $^ $(LDLIBS) -o $@

snooper: $(OBJDIR)/snooper.o $(CMDOBJS) $(OBJDIR)/proxusb.o $(OBJDIR)/guidummy.o
	$(CXX) $(CXXFLAGS) $^ $(LDLIBS) -o $@

cli: $(OBJDIR)/cli.o $(CMDOBJS) $(OBJDIR)/proxusb.o $(OBJDIR)/guidummy.o
	$(CXX) $(CXXFLAGS) $^ $(LDLIBS) -o $@

flasher: $(OBJDIR)/flash.o $(OBJDIR)/flasher.o $(OBJDIR)/proxusb.o
	$(CXX) $(CXXFLAGS) $^ $(LDLIBS) -o $@

$(OBJDIR)/%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(OBJDIR)/%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

proxguiqt.moc.cpp: proxguiqt.h
	$(MOC) -o$@ $^

clean:
	$(RM) $(CLEAN)

tarbin: $(BINS)
	$(TAR) $(TARFLAGS) ../proxmark3-$(platform)-bin.tar $(BINS:%=client/%)

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
