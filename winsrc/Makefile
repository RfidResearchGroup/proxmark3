CC=cl
BASE_DEFS   = /D_WIN32_WINNT=0x501 /DISOLATION_AWARE_ENABLED /D_WIN32_IE=0x600 /DWIN32_LEAN_AND_MEAN /DWIN32 /D_MT /D_CRT_SECURE_NO_WARNINGS
BASE_CFLAGS = /W3 /nologo /Zi /MT /Fdobj/vc90.pdb
LIB=..\..\devkitWIN\lib;%LIB%

DEFINES  = $(BASE_DEFS)
INCLUDES = /I..\..\devkitWIN/include
CFLAGS   = $(BASE_CFLAGS) $(INCLUDES)

OBJDIR = obj

OBJS   = $(OBJDIR)\prox.obj \
         $(OBJDIR)\gui.obj \
         $(OBJDIR)\command.obj

LIBS   = user32.lib gdi32.lib setupapi.lib

all: proxmark3

proxmark3:
	$(CC) $(CFLAGS) $(DEFINES) -c -Foobj/prox.obj prox.cpp
	$(CC) $(CFLAGS) $(DEFINES) -c -Foobj/gui.obj gui.cpp
	$(CC) $(CFLAGS) $(DEFINES) -c -Foobj/command.obj command.cpp
	$(CC) $(CFLAGS) $(DEFINES) -Fe$(OBJDIR)/prox.exe $(OBJS) $(LIBS)
	copy obj\prox.exe .

clean:
	del /q obj\*.obj
	del /q obj\*.ilk
	del /q obj\*.exe
	del /q obj\*.pdb
	del prox.exe