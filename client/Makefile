#-----------------------------------------------------------------------------
# This code is licensed to you under the terms of the GNU GPL, version 2 or,
# at your option, any later version. See the LICENSE.txt file for the text of
# the license.
#-----------------------------------------------------------------------------

# This Makefile might have been called directly, not via the root Makefile, so:
ifeq ($(PLTNAME),)
  -include ../Makefile.platform
  ifeq ($(PLATFORM),)
    PLATFORM=PM3RDV4
  else
    ${info using saved PLATFORM '$(PLATFORM)'}
  endif
  include ../common/Makefile.hal
  $(info ===================================================================)
  $(info PLATFORM: $(PLATFORM))
  $(info $(PLTNAME))
  $(info Included supports: $(PLATFORM_DEFS))
  $(info ===================================================================)
endif

# reveng will compile without macros, but these may be useful:
# Add -DBMPMACRO to use bitmap size constant macros (edit config.h)
# Add -DNOFORCE  to disable the -F switch
# Add -DPRESETS  to compile with preset models (edit config.h)

CC = gcc
CXX = g++
LD = g++
TAR = tar
TARFLAGS = -C .. --ignore-failed-read -rvf
RM = rm -f
MV = mv

ENV_LDFLAGS := $(LDFLAGS)
ENV_CFLAGS := $(CFLAGS)

VPATH = ../common ../zlib ../uart
OBJDIR = obj

LDLIBS = -L/opt/local/lib -L/usr/local/lib -lreadline -lpthread -lm
LUALIB = ../liblua/liblua.a
JANSSONLIBPATH = ./jansson
JANSSONLIB = $(JANSSONLIBPATH)/libjansson.a
MBEDTLSLIBPATH = ../common/mbedtls
MBEDTLSLIB = $(MBEDTLSLIBPATH)/libmbedtls.a
CBORLIBPATH = ./tinycbor
CBORLIB = $(CBORLIBPATH)/tinycbor.a
LIBS = -I../zlib -I../uart -I../liblua -I$(MBEDTLSLIBPATH) -I$(JANSSONLIBPATH) -I$(CBORLIBPATH)
INCLUDES_CLIENT = -I. -I../include -I../common -I/opt/local/include $(LIBS)
LDFLAGS = $(ENV_LDFLAGS)
CFLAGS = $(ENV_CFLAGS) -std=c99 -D_ISOC99_SOURCE -DPRESETS $(INCLUDES_CLIENT) -Wall -g -O3
CXXFLAGS = -I../include -Wall -O3

LUAPLATFORM = generic
platform = $(shell uname)
ifneq (,$(findstring MINGW,$(platform)))
    LUAPLATFORM = mingw
else
	ifeq ($(platform),Darwin)
    LUAPLATFORM = macosx
	OBJCSRCS = util_darwin.m
	LDFLAGS += -framework Foundation -framework AppKit
else
    LUALIB +=  -ldl
    LDLIBS +=  -ltermcap -lncurses
    LUAPLATFORM = linux
endif
endif

# Check for correctly configured Qt5
QTINCLUDES = $(shell pkg-config --cflags Qt5Core Qt5Widgets 2>/dev/null)
QTLDLIBS = $(shell pkg-config --libs Qt5Core Qt5Widgets 2>/dev/null)
MOC = $(shell pkg-config --variable=host_bins Qt5Core)/moc
UIC = $(shell pkg-config --variable=host_bins Qt5Core)/uic
ifeq ($(QTINCLUDES), )
# if Qt5 not found check for correctly configured Qt4
	QTINCLUDES = $(shell pkg-config --cflags QtCore QtGui 2>/dev/null)
	QTLDLIBS = $(shell pkg-config --libs QtCore QtGui 2>/dev/null)
	MOC = $(shell pkg-config --variable=moc_location QtCore)
	UIC = $(shell pkg-config --variable=uic_location QtCore)
else
	CXXFLAGS += -std=c++11 -fPIC
endif
ifeq ($(QTINCLUDES), )
# if both pkg-config commands failed, search in common places
	ifneq ($(QTDIR), )
		QTINCLUDES = -I$(QTDIR)/include -I$(QTDIR)/include/QtCore -I$(QTDIR)/include/QtGui
		QTLDLIBS = -L$(QTDIR)/lib -lQtCore4 -lQtGui4
		ifneq ($(wildcard $(QTDIR)/include/QtWidgets),)
			QTINCLUDES += -I$(QTDIR)/include/QtWidgets
			QTLDLIBS = -L$(QTDIR)/lib -lQt5Widgets -lQt5Gui -lQt5Core
			CXXFLAGS += -std=c++11 -fPIC
		endif
		MOC = $(QTDIR)/bin/moc
		UIC = $(QTDIR)/bin/uic
	endif
endif


ifneq ($(QTLDLIBS),)
    QTGUIOBJS = $(OBJDIR)/proxgui.o $(OBJDIR)/proxguiqt.o $(OBJDIR)/proxguiqt.moc.o
    CFLAGS += -DHAVE_GUI
else
    QTGUIOBJS = $(OBJDIR)/guidummy.o
endif

CFLAGS += $(PLATFORM_DEFS)

# Flags to generate temporary dependency files
DEPFLAGS = -MT $@ -MMD -MP -MF $(OBJDIR)/$*.Td
# make temporary to final dependeny files after successful compilation
POSTCOMPILE = $(MV) -f $(OBJDIR)/$*.Td $(OBJDIR)/$*.d

CORESRCS =  uart_posix.c \
			uart_win32.c \
			ui.c \
			util.c \
			util_posix.c \
			scandir.c \
			comms.c

CMDSRCS =	crapto1/crapto1.c \
			crapto1/crypto1.c \
			mifare/mfkey.c \
			tea.c \
			fido/additional_ca.c \
			fido/cose.c \
			fido/cbortools.c \
			fido/fidocore.c \
			crypto/asn1dump.c \
			crypto/libpcrypto.c\
			crypto/asn1utils.c\
			cliparser/argtable3.c\
			cliparser/cliparser.c\
			loclass/cipher.c \
			loclass/cipherutils.c \
			loclass/ikeys.c \
			loclass/hash1_brute.c \
			loclass/elite_crack.c \
			loclass/fileutils.c \
			whereami.c \
			mifare/mifarehost.c \
			parity.c \
			crc.c \
			crc16.c \
			crc64.c \
			legic_prng.c \
			iso15693tools.c \
			prng.c \
			graph.c \
			cmddata.c \
			lfdemod.c \
			emv/crypto_polarssl.c\
			emv/crypto.c\
			emv/emv_pk.c\
			emv/emv_pki.c\
			emv/emv_pki_priv.c\
			emv/test/cryptotest.c\
			emv/apduinfo.c \
			emv/dump.c \
			emv/tlv.c \
			emv/emv_tags.c \
			emv/dol.c \
			emv/emvjson.c\
			emv/emvcore.c \
			emv/test/crypto_test.c\
			emv/test/sda_test.c\
			emv/test/dda_test.c\
			emv/test/cda_test.c\
			emv/cmdemv.c \
			emv/emv_roca.c \
            mifare/mifare4.c \
            mifare/mad.c \
            mifare/ndef.c \
			cmdanalyse.c \
			cmdhf.c \
			cmdhflist.c \
			cmdhf14a.c \
			cmdhf14b.c \
			cmdhf15.c \
			cmdhfepa.c \
			cmdhflegic.c \
			cmdhficlass.c \
			cmdhfmf.c \
            cmdhfmfu.c \
            cmdhfmfp.c \
			cmdhfmfhard.c \
            hardnested/hardnested_bruteforce.c \
			cmdhfmfdes.c \
			cmdhftopaz.c \
			cmdhffido.c \
			cmdhffelica.c \
			cmdhw.c \
			cmdlf.c \
			cmdlfawid.c \
			cmdlfcotag.c \
			cmdlfem4x.c \
			cmdlffdx.c \
			cmdlfguard.c \
			cmdlfhid.c \
			cmdlfhitag.c \
			cmdlfio.c \
			cmdlfindala.c \
			cmdlfjablotron.c \
			cmdlfkeri.c \
			cmdlfnexwatch.c \
			cmdlfnedap.c \
			cmdlfnoralsy.c \
			cmdlfpac.c \
			cmdlfparadox.c \
			cmdlfpcf7931.c \
			cmdlfpresco.c \
			cmdlfpyramid.c \
			cmdlfsecurakey.c \
			cmdlft55xx.c \
			cmdlfti.c \
			cmdlfviking.c \
			cmdlfvisa2000.c \
			cmdtrace.c \
			cmdflashmem.c \
			cmdsmartcard.c \
			cmdparser.c \
			cmdmain.c \
			pm3_binlib.c \
			scripting.c \
			cmdscript.c \
			pm3_bitlib.c \
			protocols.c \
			cmdcrc.c \
			reveng/preset.c \
			reveng/reveng.c \
			reveng/cli.c \
			reveng/bmpbit.c \
			reveng/model.c \
			reveng/poly.c \
			bucketsort.c

cpu_arch = $(shell uname -m)
ifneq ($(findstring 86, $(cpu_arch)), )
	MULTIARCHSRCS = hardnested/hardnested_bf_core.c hardnested/hardnested_bitarray_core.c
endif
ifneq ($(findstring amd64, $(cpu_arch)), )
	MULTIARCHSRCS = hardnested/hardnested_bf_core.c hardnested/hardnested_bitarray_core.c
endif
ifeq ($(MULTIARCHSRCS), )
	CMDSRCS += hardnested/hardnested_bf_core.c hardnested/hardnested_bitarray_core.c
endif

ZLIBSRCS = deflate.c adler32.c trees.c zutil.c inflate.c inffast.c inftrees.c
ZLIBFLAGS = -DZ_SOLO -DZ_PREFIX -DNO_GZIP -DZLIB_PM3_TUNED
#-DDEBUG -Dverbose=1

QTGUISRCS = proxgui.cpp proxguiqt.cpp proxguiqt.moc.cpp guidummy.cpp

COREOBJS = $(CORESRCS:%.c=$(OBJDIR)/%.o)
CMDOBJS = $(CMDSRCS:%.c=$(OBJDIR)/%.o)
OBJCOBJS = $(OBJCSRCS:%.m=$(OBJDIR)/%.o)
ZLIBOBJS = $(ZLIBSRCS:%.c=$(OBJDIR)/%.o)
MULTIARCHOBJS = $(MULTIARCHSRCS:%.c=$(OBJDIR)/%_NOSIMD.o) \
			$(MULTIARCHSRCS:%.c=$(OBJDIR)/%_MMX.o) \
			$(MULTIARCHSRCS:%.c=$(OBJDIR)/%_SSE2.o) \
			$(MULTIARCHSRCS:%.c=$(OBJDIR)/%_AVX.o) \
			$(MULTIARCHSRCS:%.c=$(OBJDIR)/%_AVX2.o)

SUPPORTS_AVX512 :=  $(shell echo | gcc -E -mavx512f - > /dev/null 2>&1 && echo "True" )

HARD_SWITCH_NOSIMD = -mno-mmx -mno-sse2 -mno-avx -mno-avx2
HARD_SWITCH_MMX = -mmmx -mno-sse2 -mno-avx -mno-avx2
HARD_SWITCH_SSE2 = -mmmx -msse2 -mno-avx -mno-avx2
HARD_SWITCH_AVX = -mmmx -msse2 -mavx -mno-avx2
HARD_SWITCH_AVX2 = -mmmx -msse2 -mavx -mavx2
HARD_SWITCH_AVX512 = -mmmx -msse2 -mavx -mavx2 -mavx512f
ifeq "$(SUPPORTS_AVX512)" "True"
	HARD_SWITCH_NOSIMD += -mno-avx512f
	HARD_SWITCH_MMX += -mno-avx512f
	HARD_SWITCH_SSE2 += -mno-avx512f
	HARD_SWITCH_AVX += -mno-avx512f
	HARD_SWITCH_AVX2 += -mno-avx512f
	MULTIARCHOBJS +=  $(MULTIARCHSRCS:%.c=$(OBJDIR)/%_AVX512.o)
endif

BINS = proxmark3 flasher fpga_compress
WINBINS = $(patsubst %, %.exe, $(BINS))
CLEAN = $(BINS) $(WINBINS) $(COREOBJS) $(CMDOBJS) $(OBJCOBJS) $(ZLIBOBJS) $(QTGUIOBJS) $(MULTIARCHOBJS) $(OBJDIR)/*.o *.moc.cpp ui/ui_overlays.h lualibs/usb_cmd.lua lualibs/mf_default_keys.lua

# need to assign dependancies to build these first...
all: lua_build jansson_build mbedtls_build cbor_build $(BINS)

all-static: LDLIBS:=-static $(LDLIBS)
all-static: proxmark3 flasher fpga_compress

proxmark3: LDLIBS+=$(LUALIB) $(JANSSONLIB) $(MBEDTLSLIB) $(CBORLIB) $(QTLDLIBS)
proxmark3: $(OBJDIR)/proxmark3.o $(COREOBJS) $(CMDOBJS) $(OBJCOBJS) $(QTGUIOBJS) $(MULTIARCHOBJS) $(ZLIBOBJS) lualibs/usb_cmd.lua lualibs/mf_default_keys.lua
	$(LD) $(LDFLAGS) $(OBJDIR)/proxmark3.o $(COREOBJS) $(CMDOBJS) $(OBJCOBJS) $(QTGUIOBJS) $(MULTIARCHOBJS) $(ZLIBOBJS) $(LDLIBS)  -o $@

flasher: $(OBJDIR)/flash.o $(OBJDIR)/flasher.o $(COREOBJS) $(OBJCOBJS)
	$(LD) $(LDFLAGS) $^ $(LDLIBS) -o $@

fpga_compress: $(OBJDIR)/fpga_compress.o $(ZLIBOBJS)
	$(LD) $(LDFLAGS) $(ZLIBFLAGS) $^ $(LDLIBS) -o $@

proxgui.cpp: ui/ui_overlays.h

proxguiqt.moc.cpp: proxguiqt.h
	$(MOC) -o$@ $^

ui/ui_overlays.h: ui/overlays.ui
	$(UIC) $^ > $@

lualibs/usb_cmd.lua: ../include/usb_cmd.h
	awk -f usb_cmd_h2lua.awk $^ > $@

lualibs/mf_default_keys.lua : default_keys.dic
	awk -f default_keys_dic2lua.awk $^ > $@

clean:
	$(RM) $(CLEAN)
	cd ../liblua && $(MAKE) clean
	cd $(JANSSONLIBPATH) && $(MAKE) clean
	cd $(MBEDTLSLIBPATH) && $(MAKE) clean
	cd $(CBORLIBPATH) && $(MAKE) clean

tarbin: $(BINS)
	$(TAR) $(TARFLAGS) ../proxmark3-$(platform)-bin.tar $(BINS:%=client/%) $(WINBINS:%=client/%)

lua_build:
	@echo Compiling liblua, using platform $(LUAPLATFORM)
	cd ../liblua && $(MAKE) $(LUAPLATFORM)

jansson_build:
	@echo Compiling jansson
	cd $(JANSSONLIBPATH) && $(MAKE) all

mbedtls_build:
	@echo Compiling mbedtls
	cd $(MBEDTLSLIBPATH) && $(MAKE) all

cbor_build:
	@echo Compiling tinycbor
	cd $(CBORLIBPATH) && $(MAKE) all

.PHONY: all clean

# easy printing of MAKE VARIABLES
print-%: ; @echo $* = $($*)

$(OBJDIR)/%_NOSIMD.o : %.c $(OBJDIR)/%_NOSIMD.d
	$(CC) $(DEPFLAGS) $(CFLAGS) $(HARD_SWITCH_NOSIMD) -c -o $@ $<
	$(POSTCOMPILE:%.d=%_NOSIMD.d)

$(OBJDIR)/%_MMX.o : %.c $(OBJDIR)/%_MMX.d
	$(CC) $(DEPFLAGS) $(CFLAGS) $(HARD_SWITCH_MMX) -c -o $@ $<
	$(POSTCOMPILE:%.d=%_MMX.d)

$(OBJDIR)/%_SSE2.o : %.c $(OBJDIR)/%_SSE2.d
	$(CC) $(DEPFLAGS) $(CFLAGS) $(HARD_SWITCH_SSE2) -c -o $@ $<
	$(POSTCOMPILE:%.d=%_SSE2.d)

$(OBJDIR)/%_AVX.o : %.c $(OBJDIR)/%_AVX.d
	$(CC) $(DEPFLAGS) $(CFLAGS) $(HARD_SWITCH_AVX) -c -o $@ $<
	$(POSTCOMPILE:%.d=%_AVX.d)

$(OBJDIR)/%_AVX2.o : %.c $(OBJDIR)/%_AVX2.d
	$(CC) $(DEPFLAGS) $(CFLAGS) $(HARD_SWITCH_AVX2) -c -o $@ $<
	$(POSTCOMPILE:%.d=%_AVX2.d)

$(OBJDIR)/%_AVX512.o : %.c $(OBJDIR)/%_AVX512.d
	$(CC) $(DEPFLAGS) $(CFLAGS) $(HARD_SWITCH_AVX512) -c -o $@ $<
	$(POSTCOMPILE:%.d=%_AVX512.d)

%.o: %.c
$(OBJDIR)/%.o : %.c $(OBJDIR)/%.d
	$(CC) $(DEPFLAGS) $(CFLAGS) $(ZLIBFLAGS) -c -o $@ $<
	$(POSTCOMPILE)

%.o: %.cpp
$(OBJDIR)/%.o : %.cpp $(OBJDIR)/%.d
	$(CXX) $(DEPFLAGS) $(CXXFLAGS) $(QTINCLUDES) -c -o $@ $<
	$(POSTCOMPILE)

%.o: %.m
$(OBJDIR)/%.o : %.m $(OBJDIR)/%.d
	$(CC) $(DEPFLAGS) $(CFLAGS) -c -o $@ $<
	$(POSTCOMPILE)

#$(CMDOBJS) $(COREOBJS): $(notdir $(%.c)) %.d
#	$(CC) $(DEPFLAGS) $(CFLAGS) -c -o $@ $<
#	$(POSTCOMPILE)

#$(ZLIBOBJS): $(notdir $(%.c)) %.d
#	$(CC) $(DEPFLAGS) $(CFLAGS) $(ZLIBFLAGS) -c -o $@ $<
#	$(POSTCOMPILE)

#$(QTGUIOBJS): $(notdir $(%.cpp)) %.d
#	$(CXX) $(DEPFLAGS) $(CXXFLAGS) -c -o $@ $<
#	$(POSTCOMPILE)

DEPENDENCY_FILES = $(patsubst %.c, $(OBJDIR)/%.d, $(CORESRCS) $(CMDSRCS) $(ZLIBSRCS)) \
	$(patsubst %.o, %.d, $(MULTIARCHOBJS)) \
	$(patsubst %.cpp, $(OBJDIR)/%.d, $(QTGUISRCS)) \
	$(patsubst %.m, $(OBJDIR)/%.d, $(OBJCSRCS)) \
	$(OBJDIR)/proxmark3.d $(OBJDIR)/flash.d $(OBJDIR)/flasher.d $(OBJDIR)/fpga_compress.d

$(DEPENDENCY_FILES): ;
.PRECIOUS: $(DEPENDENCY_FILES)

-include $(DEPENDENCY_FILES)

