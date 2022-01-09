MYSRCPATHS = ../common
MYSRCS = ht2crackutils.c hitagcrypto.c
MYCFLAGS =
MYDEFS =

platform = $(shell uname)

ifeq ($(platform),Darwin)
    MYLDLIBS ?= -framework OpenCL
else
    #MYINCLUDES ?=-I/usr/local/cuda-7.5/include
    #MYINCLUDES ?=-I/opt/nvidia/cuda/include
    #MYLDLIBS ?= -L/usr/local/cuda-7.5/lib64 -lOpenCL
    MYLDLIBS ?= -L/opt/nvidia/cuda/lib64 -lOpenCL
endif
MYINCLUDES +=-I ../common
MYINCLUDES +=-I ../common/OpenCL-Headers

BINS = ht2crack5gpu
INSTALLTOOLS = $(BINS)

include ../../../Makefile.host

# checking platform can be done only after Makefile.host
ifneq (,$(findstring MINGW,$(platform)))
    # Mingw uses by default Microsoft printf, we want the GNU printf (e.g. for %z)
    # and setting _ISOC99_SOURCE sets internally __USE_MINGW_ANSI_STDIO=1
    CFLAGS += -D_ISOC99_SOURCE
endif

ht2crack5gpu : $(OBJDIR)/ht2crack5gpu.o $(MYOBJS)
