MYSRCS = queue.c threads.c opencl.c hitag2.c
MYCFLAGS =
MYDEFS = -D TEST_UNIT=0

platform = $(shell uname)

ifeq ($(platform),Darwin)
    MYLDLIBS ?= -framework OpenCL
else
    #MYINCLUDES ?=-I/usr/local/cuda-7.5/include
    #MYINCLUDES ?=-I/opt/nvidia/cuda/include
    #MYLDLIBS ?= -L/usr/local/cuda-7.5/lib64 -lOpenCL
    MYLDLIBS ?= -L/opt/nvidia/cuda/lib64 -lOpenCL
endif
MYLDLIBS += -lpthread

MYINCLUDES +=-I ../common
MYINCLUDES +=-I ../common/OpenCL-Headers

BINS = ht2crack5opencl
INSTALLTOOLS = $(BINS)

include ../../../Makefile.host

# checking platform can be done only after Makefile.host
ifneq (,$(findstring MINGW,$(platform)))
    # Mingw uses by default Microsoft printf, we want the GNU printf (e.g. for %z)
    # and setting _ISOC99_SOURCE sets internally __USE_MINGW_ANSI_STDIO=1
    CFLAGS += -D_ISOC99_SOURCE
endif

WITH_CLANG=$(shell $(CC) --version 2>&1 | grep -c "clang")

# disable sanitize on Linux
ifeq ($(SANITIZE),1)
ifeq ($(platform),Linux)

CFLAGS := $(filter-out -fsanitize=address,$(CFLAGS))
CFLAGS := $(filter-out -fno-omit-frame-pointer,$(CFLAGS))
LDFLAGS := $(filter-out -fsanitize=address,$(CFLAGS))

define errMsg
Disabling SANITIZE here, is incompatibe with OpenCL on Linux, due to a bug.
Check this (https://github.com/google/sanitizers/issues/611).
endef
$(warning $(errMsg))
endif
endif

# clang
ifeq ($(WITH_CLANG),1)
ifeq ($(platform),Linux)
CFLAGS += -fPIE
endif
endif

# if debug and clang, add more CFLAGS
ifeq ($(DEBUG),1)
ifeq ($(WITH_CLANG),1)
CFLAGS += -Weverything
CFLAGS += -Wno-reserved-id-macro
ifeq ($(platform),Linux)
CFLAGS += -Wno-error=reserved-id-macro
CFLAGS += -Wno-error=disabled-macro-expansion
endif
endif
$(info CFLAGS are: $(CFLAGS))
endif

ht2crack5opencl : $(OBJDIR)/ht2crack5opencl.o ${MYOBJS}

ifeq ($(platform),Darwin)
ht2crack5opencl_clean:
	@rm -rf *.dSYM

clean: ht2crack5opencl_clean
endif
