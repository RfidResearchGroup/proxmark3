LDFLAGS = -ltermcap -lusb -lreadline -lpthread -L/opt/local/lib
CFLAGS = -I. -I/opt/local/include -Wall

CXXFLAGS = $(shell pkg-config --cflags QtCore QtGui 2>/dev/null) -Wall
QTLDFLAGS = $(shell pkg-config --libs QtCore QtGui 2>/dev/null)

ifneq ($(QTLDFLAGS),)
QTGUI = proxgui.o proxguiqt.o proxguiqt.moc.o
CFLAGS += -DHAVE_GUI
MOC = $(shell type moc-qt4 >/dev/null 2>&1 && echo moc-qt4 || echo moc)
LINK.o = $(LINK.cpp)
else
QTGUI = guidummy.o
endif

all: proxmark3 snooper cli flasher

proxmark3: LDFLAGS+=$(QTLDFLAGS)
proxmark3: proxmark3.o gui.o command.o usb.o $(QTGUI)

command.o: ../winsrc/command.cpp translate.h

snooper: snooper.o gui.o command.o usb.o guidummy.o

cli: cli.o gui.o command.o usb.o guidummy.o

flasher: flasher.o usb.o

proxguiqt.moc.cpp: proxguiqt.h
	$(MOC) -o$@ $^

clean:
	rm -f cli flasher proxmark3 snooper *.o *.moc.cpp

.PHONY: all clean
