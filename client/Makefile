WINCC=c:\mingw\bin\gcc
#COMMON_FLAGS = -m32

VPATH = ../common

LDLIBS = -L/opt/local/lib -L/usr/local/lib -lusb -lreadline -lpthread
LDFLAGS = $(COMMON_FLAGS)
CFLAGS = -std=c99 -I. -I../include -I../common -I/opt/local/include -Wall -Wno-unused-function $(COMMON_FLAGS) -g3

WINLIBS = -lgdi32 -lsetupapi
CXXFLAGS = $(shell pkg-config --cflags QtCore QtGui 2>/dev/null) -Wall
QTLDLIBS = $(shell pkg-config --libs QtCore QtGui 2>/dev/null)

CMDSRCS = \
			crc16.c \
			iso14443crc.c \
			data.c \
			graph.c \
			ui.c \
			cmddata.c \
			cmdhf.c \
			cmdhf14a.c \
			cmdhf14b.c \
			cmdhf15.c \
			cmdhflegic.c \
			cmdhw.c \
			cmdlf.c \
			cmdlfem4x.c \
			cmdlfhid.c \
			cmdlfti.c \
			cmdparser.c \
			cmdmain.c

CMDOBJS = $(CMDSRCS:.c=.o)

ifeq ($(shell echo ""),)

ifeq ($(shell uname),Darwin)
CXXFLAGS = -I/Library/Frameworks/QtGui.framework/Versions/Current/Headers -I/Library/Frameworks/QtCore.framework/Versions/Current/Headers
QTLDLIBS = -framework QtGui -framework QtCore
MOC = moc
endif

ifneq ($(QTLDLIBS),)
QTGUI = proxgui.o proxguiqt.o proxguiqt.moc.o
CFLAGS += -DHAVE_GUI
MOC ?= $(shell pkg-config --variable=moc_location QtCore)
LINK.o = $(LINK.cpp)
else
QTGUI = guidummy.o
endif

RM = rm -f
BINS = proxmark3 snooper cli flasher
CLEAN = cli flasher proxmark3 snooper *.o $(CMDOBJS) *.moc.cpp
else
RM = del
BINS = prox.exe
CLEAN = prox.exe
endif

all: $(BINS)

all-static: LDLIBS:=-static $(LDLIBS)
all-static: snooper cli flasher

prox.exe: prox.c wingui.c $(CMDSRCS) flash.c
	$(WINCC) $(CFLAGS) $(DEFINES) -o prox.exe prox.c wingui.c $(CMDSRCS) flash.c $(WINLIBS)
	
proxmark3: LDLIBS+=$(QTLDLIBS)
proxmark3: proxmark3.o $(CMDOBJS) proxusb.o $(QTGUI)

snooper: snooper.o $(CMDOBJS) proxusb.o guidummy.o

cli: cli.o $(CMDOBJS) proxusb.o guidummy.o

flasher: flash.o flasher.o proxusb.o

proxguiqt.moc.cpp: proxguiqt.h
	$(MOC) -o$@ $^

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
