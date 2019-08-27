#-----------------------------------------------------------------------------
# This code is licensed to you under the terms of the GNU GPL, version 2 or,
# at your option, any later version. See the LICENSE.txt file for the text of
# the license.
#-----------------------------------------------------------------------------

# reveng will compile without macros, but these may be useful:
# Add -DBMPMACRO to use bitmap size constant macros (edit config.h)
# Add -DNOFORCE  to disable the -F switch
# Add -DPRESETS  to compile with preset models (edit config.h)

# Hide full compilation line:
ifneq ($(V),1)
  Q?=@
endif
# To see full command lines, use make V=1

CC = gcc
CXX = g++
LD = g++
TAR = tar
TARFLAGS ?= -v --ignore-failed-read -r
TARFLAGS += -C .. -f
RM = rm -f
RMDIR= rm -rf
MKDIR = mkdir -p
MV = mv
TOUCH = touch
FALSE = false

platform = $(shell uname)
ROOT_DIR:=$(dir $(realpath $(lastword $(MAKEFILE_LIST))))

VPATH = ../common uart
vpath %.dic dictionaries
OBJDIR = obj

LDLIBS ?= -L/usr/local/lib
LDLIBS += -lreadline -lpthread -lm

# RPi Zero gcc requires -latomic
# but MacOSX /Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/ld
# doesn't recognize option --as-needed
ifneq ($(platform),Darwin)
    LDLIBS += -Wl,--as-needed -latomic -Wl,--no-as-needed
endif

# local libraries
LUALIBPATH = ./liblua
LUALIB = $(LUALIBPATH)/liblua.a
JANSSONLIBPATH = ./jansson
JANSSONLIB = $(JANSSONLIBPATH)/libjansson.a
CBORLIBPATH = ./tinycbor
CBORLIB = $(CBORLIBPATH)/tinycbor.a
REVENGPATH = ./reveng
REVENGLIB = $(REVENGPATH)/libreveng.a

# common libraries
MBEDTLSLIBPATH = ../common/mbedtls
MBEDTLSLIB = $(OBJDIR)/libmbedtls.a
ZLIBPATH = ../common/zlib
ZLIB = $(OBJDIR)/libz.a

LIBS = -I$(LUALIBPATH) -I$(MBEDTLSLIBPATH) -I$(JANSSONLIBPATH) -I$(CBORLIBPATH) -I$(ZLIBPATH) -I$(REVENGPATH)
INCLUDES_CLIENT = -I. -I../include -I../common -Iuart $(LIBS)
CFLAGS ?= -Wall -Werror -g -O3
# We cannot just use CFLAGS+=... because it has impact on sub-makes if CFLAGS is defined in env:
PM3CFLAGS = $(CFLAGS) -std=c99 -D_ISOC99_SOURCE $(INCLUDES_CLIENT)
ifneq (,$(PM3_BIN_PATH))
    PM3CFLAGS += -DPM3_BIN_PATH=\"$(PM3_BIN_PATH)\"
endif
ifneq (,$(PM3_SHARE_PATH))
    PM3CFLAGS += -DPM3_SHARE_PATH=\"$(PM3_SHARE_PATH)\"
endif
ifneq (,$(findstring MINGW,$(platform)))
    PM3CFLAGS += -mno-ms-bitfields -fexec-charset=cp850
endif
CXXFLAGS ?= -Wall -Werror -O3
PM3CXXFLAGS = $(CXXFLAGS) -I../include

LUAPLATFORM = generic
ifneq (,$(findstring MINGW,$(platform)))
    LUAPLATFORM = mingw
else
    ifeq ($(platform),Darwin)
    LUAPLATFORM = macosx
    OBJCSRCS = util_darwin.m
    LDFLAGS += -framework Foundation -framework AppKit
    LDLIBS := -L/usr/local/opt/readline/lib $(LDLIBS)
    LIBS := -I/usr/local/opt/readline/include $(LIBS)
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
    PM3CXXFLAGS += -std=c++11 -fPIC
endif
ifeq ($(QTINCLUDES), )
# if both pkg-config commands failed, search in common places
    ifneq ($(QTDIR), )
        QTINCLUDES = -I$(QTDIR)/include -I$(QTDIR)/include/QtCore -I$(QTDIR)/include/QtGui
        QTLDLIBS = -L$(QTDIR)/lib -lQtCore4 -lQtGui4
        ifneq ($(wildcard $(QTDIR)/include/QtWidgets),)
            QTINCLUDES += -I$(QTDIR)/include/QtWidgets
            QTLDLIBS = -L$(QTDIR)/lib -lQt5Widgets -lQt5Gui -lQt5Core
            PM3CXXFLAGS += -std=c++11 -fPIC
        endif
        MOC = $(QTDIR)/bin/moc
        UIC = $(QTDIR)/bin/uic
    endif
endif


ifneq ($(QTLDLIBS),)
    QTGUIOBJS = $(OBJDIR)/proxgui.o $(OBJDIR)/proxguiqt.o $(OBJDIR)/proxguiqt.moc.o
    PM3CFLAGS += -DHAVE_GUI
else
    QTGUIOBJS = $(OBJDIR)/guidummy.o
endif

# Flags to generate temporary dependency files
DEPFLAGS = -MT $@ -MMD -MP -MF $(OBJDIR)/$*.Td
# make temporary to final dependency files after successful compilation
POSTCOMPILE = $(MV) -f $(OBJDIR)/$*.Td $(OBJDIR)/$*.d && $(TOUCH) $@

CORESRCS =  uart_posix.c \
            uart_win32.c \
            ui.c \
            commonutil.c \
            util.c \
            util_posix.c \
            scandir.c \
            crc16.c \
            comms.c

CMDSRCS =   crapto1/crapto1.c \
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
            loclass/elite_crack.c \
            fileutils.c \
            whereami.c \
            mifare/mifarehost.c \
            parity.c \
            crc.c \
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
            cmdhfthinfilm.c \
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
            cmdflashmemspiffs.c \
            cmdsmartcard.c \
            cmdusart.c \
            cmdparser.c \
            cmdmain.c \
            pm3_binlib.c \
            scripting.c \
            cmdscript.c \
            pm3_bitlib.c \
            cmdcrc.c \
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

QTGUISRCS = proxgui.cpp proxguiqt.cpp proxguiqt.moc.cpp guidummy.cpp

COREOBJS = $(CORESRCS:%.c=$(OBJDIR)/%.o)
CMDOBJS = $(CMDSRCS:%.c=$(OBJDIR)/%.o)
OBJCOBJS = $(OBJCSRCS:%.m=$(OBJDIR)/%.o)
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

BINS = proxmark3 flasher
CLEAN = $(BINS) *.moc.cpp ui/ui_overlays.h lualibs/pm3_cmd.lua lualibs/mfc_default_keys.lua

# need to assign dependancies to build these first...
all: $(BINS)

all-static: LDLIBS:=-static $(LDLIBS)
all-static: $(BINS)

proxmark3: LDLIBS+=$(LUALIB) $(JANSSONLIB) $(MBEDTLSLIB) $(CBORLIB) $(ZLIB) $(REVENGLIB) $(QTLDLIBS)
proxmark3: $(OBJDIR)/proxmark3.o $(COREOBJS) $(CMDOBJS) $(OBJCOBJS) $(QTGUIOBJS) $(MULTIARCHOBJS) $(LUALIB) $(JANSSONLIB) $(CBORLIB) $(REVENGLIB) $(MBEDTLSLIB) $(ZLIB) lualibs/pm3_cmd.lua lualibs/mfc_default_keys.lua
	$(info [=] LD $@)
	$(Q)$(LD) $(LDFLAGS) $(OBJDIR)/proxmark3.o $(COREOBJS) $(CMDOBJS) $(OBJCOBJS) $(QTGUIOBJS) $(MULTIARCHOBJS) $(LDLIBS)  -o $@

flasher: $(OBJDIR)/flash.o $(OBJDIR)/flasher.o $(COREOBJS) $(OBJCOBJS)
	$(info [=] LD $@)
	$(Q)$(LD) $(LDFLAGS) $^ $(LDLIBS) -o $@

proxgui.cpp: ui/ui_overlays.h

proxguiqt.moc.cpp: proxguiqt.h
	$(info [-] MOC $@)
	$(Q)$(MOC) -o$@ $^

ui/ui_overlays.h: ui/overlays.ui
	$(info [-] UIC $@)
	$(Q)$(UIC) $^ > $@

lualibs/pm3_cmd.lua: ../include/pm3_cmd.h
	$(info [=] GEN $@)
	$(Q)awk -f pm3_cmd_h2lua.awk $^ > $@

lualibs/mfc_default_keys.lua : mfc_default_keys.dic
	$(info [=] GEN $@)
	$(Q)awk -f default_keys_dic2lua.awk $^ > $@

clean:
	$(Q)$(RM) $(CLEAN)
	$(Q)$(RMDIR) $(OBJDIR)
	$(Q)$(MAKE) --no-print-directory -C $(LUALIBPATH) clean
	$(Q)$(MAKE) --no-print-directory -C $(JANSSONLIBPATH) clean
	$(Q)$(MAKE) --no-print-directory -C $(CBORLIBPATH) clean
	$(Q)$(MAKE) --no-print-directory -C $(REVENGPATH) clean

tarbin: $(BINS)
	$(info [=] TAR ../proxmark3-$(platform)-bin.tar)
	$(Q)$(TAR) $(TARFLAGS) ../proxmark3-$(platform)-bin.tar $(BINS:%=client/%) $(WINBINS:%=client/%)

# local libraries:
$(LUALIB):
	$(info [*] MAKE liblua for $(LUAPLATFORM))
	$(Q)$(MAKE) --no-print-directory -C $(LUALIBPATH) $(LUAPLATFORM)

$(JANSSONLIB):
	$(info [*] MAKE jansson)
	$(Q)$(MAKE) --no-print-directory -C $(JANSSONLIBPATH) all

$(CBORLIB):
	$(info [*] MAKE tinycbor)
	$(Q)$(MAKE) --no-print-directory -C $(CBORLIBPATH) all

$(REVENGLIB):
	$(info [*] MAKE reveng)
	$(Q)$(MAKE) --no-print-directory -C $(REVENGPATH) all

# common libraries:
$(MBEDTLSLIB):
	$(info [*] MAKE mbedtls)
	$(Q)$(MAKE) --no-print-directory -C $(MBEDTLSLIBPATH) OBJDIR=$(ROOT_DIR)$(OBJDIR) BINDIR=$(ROOT_DIR)$(OBJDIR) all

$(ZLIB):
	$(info [*] MAKE zlib)
	$(Q)$(MAKE) --no-print-directory -C $(ZLIBPATH) OBJDIR=$(ROOT_DIR)$(OBJDIR) BINDIR=$(ROOT_DIR)$(OBJDIR) all

.PHONY: all clean

# easy printing of MAKE VARIABLES
print-%: ; @echo $* = $($*)

$(OBJDIR)/%_NOSIMD.o : %.c $(OBJDIR)/%_NOSIMD.d
	$(info [-] CC(NOSIMD) $<)
	$(Q)$(MKDIR) $(dir $@)
	$(Q)$(CC) $(DEPFLAGS:%.Td=%_NOSIMD.Td) $(PM3CFLAGS) $(HARD_SWITCH_NOSIMD) -c -o $@ $<
	$(Q)$(MV) -f $(OBJDIR)/$*_NOSIMD.Td $(OBJDIR)/$*_NOSIMD.d && $(TOUCH) $@

$(OBJDIR)/%_MMX.o : %.c $(OBJDIR)/%_MMX.d
	$(info [-] CC(MMX) $<)
	$(Q)$(MKDIR) $(dir $@)
	$(Q)$(CC) $(DEPFLAGS:%.Td=%_MMX.Td) $(PM3CFLAGS) $(HARD_SWITCH_MMX) -c -o $@ $<
	$(Q)$(MV) -f $(OBJDIR)/$*_MMX.Td $(OBJDIR)/$*_MMX.d && $(TOUCH) $@

$(OBJDIR)/%_SSE2.o : %.c $(OBJDIR)/%_SSE2.d
	$(info [-] CC(SSE2) $<)
	$(Q)$(MKDIR) $(dir $@)
	$(Q)$(CC) $(DEPFLAGS:%.Td=%_SSE2.Td) $(PM3CFLAGS) $(HARD_SWITCH_SSE2) -c -o $@ $<
	$(Q)$(MV) -f $(OBJDIR)/$*_SSE2.Td $(OBJDIR)/$*_SSE2.d && $(TOUCH) $@

$(OBJDIR)/%_AVX.o : %.c $(OBJDIR)/%_AVX.d
	$(info [-] CC(AVX) $<)
	$(Q)$(MKDIR) $(dir $@)
	$(Q)$(CC) $(DEPFLAGS:%.Td=%_AVX.Td) $(PM3CFLAGS) $(HARD_SWITCH_AVX) -c -o $@ $<
	$(Q)$(MV) -f $(OBJDIR)/$*_AVX.Td $(OBJDIR)/$*_AVX.d && $(TOUCH) $@

$(OBJDIR)/%_AVX2.o : %.c $(OBJDIR)/%_AVX2.d
	$(info [-] CC(AVX2) $<)
	$(Q)$(MKDIR) $(dir $@)
	$(Q)$(CC) $(DEPFLAGS:%.Td=%_AVX2.Td) $(PM3CFLAGS) $(HARD_SWITCH_AVX2) -c -o $@ $<
	$(Q)$(MV) -f $(OBJDIR)/$*_AVX2.Td $(OBJDIR)/$*_AVX2.d && $(TOUCH) $@

$(OBJDIR)/%_AVX512.o : %.c $(OBJDIR)/%_AVX512.d
	$(info [-] CC(AVX512) $<)
	$(Q)$(MKDIR) $(dir $@)
	$(Q)$(CC) $(DEPFLAGS:%.Td=%_AVX512.Td) $(PM3CFLAGS) $(HARD_SWITCH_AVX512) -c -o $@ $<
	$(Q)$(MV) -f $(OBJDIR)/$*_AVX512.Td $(OBJDIR)/$*_AVX512.d && $(TOUCH) $@

%.o: %.c
$(OBJDIR)/%.o : %.c $(OBJDIR)/%.d
	$(info [-] CC $<)
	$(Q)$(MKDIR) $(dir $@)
	$(Q)$(CC) $(DEPFLAGS) $(PM3CFLAGS) -c -o $@ $<
	$(Q)$(POSTCOMPILE)

%.o: %.cpp
$(OBJDIR)/%.o : %.cpp $(OBJDIR)/%.d
	$(info [-] CXX $<)
	$(Q)$(MKDIR) $(dir $@)
	$(Q)$(CXX) $(DEPFLAGS) $(PM3CXXFLAGS) $(QTINCLUDES) -c -o $@ $<
	$(Q)$(POSTCOMPILE)

%.o: %.m
$(OBJDIR)/%.o : %.m $(OBJDIR)/%.d
	$(info [-] CC $<)
	$(Q)$(MKDIR) $(dir $@)
	$(Q)$(CC) $(DEPFLAGS) $(PM3CFLAGS) -c -o $@ $<
	$(Q)$(POSTCOMPILE)

DEPENDENCY_FILES = $(patsubst %.c, $(OBJDIR)/%.d, $(CORESRCS) $(CMDSRCS) $(REVENGSRCS)) \
	$(patsubst %.o, %.d, $(MULTIARCHOBJS)) \
	$(patsubst %.cpp, $(OBJDIR)/%.d, $(QTGUISRCS)) \
	$(patsubst %.m, $(OBJDIR)/%.d, $(OBJCSRCS)) \
	$(OBJDIR)/proxmark3.d $(OBJDIR)/flash.d $(OBJDIR)/flasher.d

$(DEPENDENCY_FILES): ;
.PRECIOUS: $(DEPENDENCY_FILES)

-include $(DEPENDENCY_FILES)
