MYSRCPATHS =
MYINCLUDES = -I../../../common -I../../../include -I../../src -I../../include -I../jansson
MYCFLAGS =
MYDEFS =
MYSRCS = hardnested_bruteforce.c

cpu_arch = $(shell uname -m)

IS_SIMD_ARCH =
ifneq ($(findstring 86, $(cpu_arch)), )
    IS_SIMD_ARCH=x86
endif
ifneq ($(findstring amd64, $(cpu_arch)), )
    IS_SIMD_ARCH=x86
endif
ifneq ($(findstring arm, $(cpu_arch)), )
    IS_SIMD_ARCH=arm
endif
ifneq ($(findstring arm64, $(cpu_arch)), )
    IS_SIMD_ARCH=arm64
endif
ifneq ($(findstring aarch64, $(cpu_arch)), )
    IS_SIMD_ARCH=arm64
endif
ifneq ($(findstring iP, $(cpu_arch)), )
    IS_SIMD_ARCH=arm64
endif

ifneq ($(IS_SIMD_ARCH), )
    MULTIARCHSRCS = hardnested_bf_core.c hardnested_bitarray_core.c
endif
ifeq ($(MULTIARCHSRCS), )
    MYCFLAGS += -DNOSIMD_BUILD
    MYSRCS += hardnested_bf_core.c hardnested_bitarray_core.c
endif

LIB_A = libhardnested.a

MYOBJS = $(MYSRCS:%.c=$(OBJDIR)/%.o)
ifneq ($(findstring arm, $(IS_SIMD_ARCH)), )
	MYOBJS += $(MULTIARCHSRCS:%.c=$(OBJDIR)/%_NOSIMD.o) \
				$(MULTIARCHSRCS:%.c=$(OBJDIR)/%_NEON.o)
else
	MYOBJS += $(MULTIARCHSRCS:%.c=$(OBJDIR)/%_NOSIMD.o) \
				$(MULTIARCHSRCS:%.c=$(OBJDIR)/%_MMX.o) \
				$(MULTIARCHSRCS:%.c=$(OBJDIR)/%_SSE2.o) \
				$(MULTIARCHSRCS:%.c=$(OBJDIR)/%_AVX.o) \
				$(MULTIARCHSRCS:%.c=$(OBJDIR)/%_AVX2.o)
endif

SUPPORTS_AVX512 :=  $(shell echo | $(CC) -E -mavx512f - > /dev/null 2>&1 && echo "True" )

HARD_SWITCH_NOSIMD = -mno-mmx -mno-sse2 -mno-avx -mno-avx2 -DNOSIMD_BUILD
HARD_SWITCH_NEON =
HARD_SWITCH_MMX = -mmmx -mno-sse2 -mno-avx -mno-avx2
HARD_SWITCH_SSE2 = -mmmx -msse2 -mno-avx -mno-avx2
HARD_SWITCH_AVX = -mmmx -msse2 -mavx -mno-avx2
HARD_SWITCH_AVX2 = -mmmx -msse2 -mavx -mavx2
HARD_SWITCH_AVX512 = -mmmx -msse2 -mavx -mavx2 -mavx512f
ifeq ($(IS_SIMD_ARCH), arm64)
	SUPPORTS_AVX512=False
	HARD_SWITCH_NOSIMD = -DNOSIMD_BUILD
endif
ifeq ($(IS_SIMD_ARCH), arm)
	SUPPORTS_AVX512=False
	HARD_SWITCH_NEON = -mfpu=neon
	HARD_SWITCH_NOSIMD = -DNOSIMD_BUILD
endif
ifeq "$(SUPPORTS_AVX512)" "True"
    HARD_SWITCH_NOSIMD += -mno-avx512f
    HARD_SWITCH_MMX += -mno-avx512f
    HARD_SWITCH_SSE2 += -mno-avx512f
    HARD_SWITCH_AVX += -mno-avx512f
    HARD_SWITCH_AVX2 += -mno-avx512f
    MYOBJS +=  $(MULTIARCHSRCS:%.c=$(OBJDIR)/%_AVX512.o)
endif

include ../../../Makefile.host

$(OBJDIR)/%_NOSIMD.o : %.c $(OBJDIR)/%_NOSIMD.d
	$(info DEBUG $<)

$(OBJDIR)/%_NOSIMD.o : %.c $(OBJDIR)/%_NOSIMD.d
	$(info [-] CC(NOSIMD) $<)
	$(Q)$(MKDIR) $(dir $@)
	$(Q)$(CC) $(DEPFLAGS:%.Td=%_NOSIMD.Td) $(CFLAGS) $(HARD_SWITCH_NOSIMD) -c -o $@ $<
	$(Q)$(MV) -f $(OBJDIR)/$*_NOSIMD.Td $(OBJDIR)/$*_NOSIMD.d && $(TOUCH) $@

$(OBJDIR)/%_NEON.o : %.c $(OBJDIR)/%_NEON.d
	$(info [-] CC(NEON) $<)
	$(Q)$(MKDIR) $(dir $@)
	$(Q)$(CC) $(DEPFLAGS:%.Td=%_NEON.Td) $(CFLAGS) $(HARD_SWITCH_NEON) -c -o $@ $<
	$(Q)$(MV) -f $(OBJDIR)/$*_NEON.Td $(OBJDIR)/$*_NEON.d && $(TOUCH) $@

$(OBJDIR)/%_MMX.o : %.c $(OBJDIR)/%_MMX.d
	$(info [-] CC(MMX) $<)
	$(Q)$(MKDIR) $(dir $@)
	$(Q)$(CC) $(DEPFLAGS:%.Td=%_MMX.Td) $(CFLAGS) $(HARD_SWITCH_MMX) -c -o $@ $<
	$(Q)$(MV) -f $(OBJDIR)/$*_MMX.Td $(OBJDIR)/$*_MMX.d && $(TOUCH) $@

$(OBJDIR)/%_SSE2.o : %.c $(OBJDIR)/%_SSE2.d
	$(info [-] CC(SSE2) $<)
	$(Q)$(MKDIR) $(dir $@)
	$(Q)$(CC) $(DEPFLAGS:%.Td=%_SSE2.Td) $(CFLAGS) $(HARD_SWITCH_SSE2) -c -o $@ $<
	$(Q)$(MV) -f $(OBJDIR)/$*_SSE2.Td $(OBJDIR)/$*_SSE2.d && $(TOUCH) $@

$(OBJDIR)/%_AVX.o : %.c $(OBJDIR)/%_AVX.d
	$(info [-] CC(AVX) $<)
	$(Q)$(MKDIR) $(dir $@)
	$(Q)$(CC) $(DEPFLAGS:%.Td=%_AVX.Td) $(CFLAGS) $(HARD_SWITCH_AVX) -c -o $@ $<
	$(Q)$(MV) -f $(OBJDIR)/$*_AVX.Td $(OBJDIR)/$*_AVX.d && $(TOUCH) $@

$(OBJDIR)/%_AVX2.o : %.c $(OBJDIR)/%_AVX2.d
	$(info [-] CC(AVX2) $<)
	$(Q)$(MKDIR) $(dir $@)
	$(Q)$(CC) $(DEPFLAGS:%.Td=%_AVX2.Td) $(CFLAGS) $(HARD_SWITCH_AVX2) -c -o $@ $<
	$(Q)$(MV) -f $(OBJDIR)/$*_AVX2.Td $(OBJDIR)/$*_AVX2.d && $(TOUCH) $@

$(OBJDIR)/%_AVX512.o : %.c $(OBJDIR)/%_AVX512.d
	$(info [-] CC(AVX512) $<)
	$(Q)$(MKDIR) $(dir $@)
	$(Q)$(CC) $(DEPFLAGS:%.Td=%_AVX512.Td) $(CFLAGS) $(HARD_SWITCH_AVX512) -c -o $@ $<
	$(Q)$(MV) -f $(OBJDIR)/$*_AVX512.Td $(OBJDIR)/$*_AVX512.d && $(TOUCH) $@
