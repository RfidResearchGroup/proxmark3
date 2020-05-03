#-----------------------------------------------------------------------------
# This code is licensed to you under the terms of the GNU GPL, version 2 or,
# at your option, any later version. See the LICENSE.txt file for the text of
# the license.
#-----------------------------------------------------------------------------

# reveng will compile without macros, but these may be useful:
# Add -DBMPMACRO to use bitmap size constant macros (edit config.h)
# Add -DNOFORCE  to disable the -F switch
# Add -DPRESETS  to compile with preset models (edit config.h)

# Must be called before any Makefile include
ROOT_DIR:=$(dir $(realpath $(lastword $(MAKEFILE_LIST))))

include ../Makefile.defs

INSTALLBIN = proxmark3
INSTALLSHARE = cmdscripts lualibs luascripts resources dictionaries

VPATH =  ../common src
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
LUALIBPATH = ./deps/liblua
LUALIB = $(LUALIBPATH)/liblua.a
JANSSONLIBPATH = ./deps/jansson
JANSSONLIB = $(JANSSONLIBPATH)/libjansson.a
CBORLIBPATH = ./deps/tinycbor
CBORLIB = $(CBORLIBPATH)/tinycbor.a
REVENGPATH = ./deps/reveng
REVENGLIB = $(REVENGPATH)/libreveng.a
AMIIBOLIBPATH = ./deps/amiitool
AMIIBOLIB = $(AMIIBOLIBPATH)/libamiibo.a
HARDNESTEDPATH = ./deps/hardnested
HARDNESTEDLIB = $(HARDNESTEDPATH)/libhardnested.a
CLIPARSERPATH = ./deps/cliparser
CLIPARSERLIB = $(CLIPARSERPATH)/libcliparser.a

# common libraries
MBEDTLSLIBPATH = ../common/mbedtls
MBEDTLSLIB = $(OBJDIR)/libmbedtls.a
ZLIBPATH = ../common/zlib
ZLIB = $(OBJDIR)/libz.a

LIBS = -I$(LUALIBPATH) -I$(MBEDTLSLIBPATH) -I$(JANSSONLIBPATH) -I$(CBORLIBPATH) -I$(ZLIBPATH) -I$(REVENGPATH) -I$(AMIIBOLIBPATH) -I$(HARDNESTEDPATH) -I$(CLIPARSERPATH)
INCLUDES_CLIENT += -I./src -I../include -I../common -I../common_fpga $(LIBS)
CFLAGS ?= $(DEFCFLAGS)

# We cannot just use CFLAGS+=... because it has impact on sub-makes if CFLAGS is defined in env:
PM3CFLAGS = $(CFLAGS) $(INCLUDES_CLIENT)
# WIP Testing
#PM3CFLAGS = $(CFLAGS) -std=c11 -pedantic $(INCLUDES_CLIENT)
PREFIX ?= /usr/local
ifneq (,$(findstring MINGW,$(platform)))
    # Mingw uses by default Microsoft printf, we want the GNU printf (e.g. for %z)
    # and setting _ISOC99_SOURCE sets internally __USE_MINGW_ANSI_STDIO=1
    # FTR __USE_MINGW_ANSI_STDIO seems deprecated in Mingw32
    # but not Mingw64 https://fr.osdn.net/projects/mingw/lists/archive/users/2019-January/000199.html
    PM3CFLAGS += -D_ISOC99_SOURCE
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
    # cf brew info qt: qt not symlinked anymore
    PKG_CONFIG_ENV := PKG_CONFIG_PATH=/usr/local/opt/qt/lib/pkgconfig
else
    LUALIB +=  -ldl
    LUAPLATFORM = linux
endif
endif

ifneq ($(SKIPBT),1)
    BTLDLIBS = $(shell $(PKG_CONFIG_ENV) pkg-config --libs bluez 2>/dev/null)
endif

ifneq ($(BTLDLIBS),)
    PM3CFLAGS += -DHAVE_BLUEZ
endif

ifneq ($(SKIPQT),1)
    # Check for correctly configured Qt5
    QTINCLUDES = $(shell $(PKG_CONFIG_ENV) pkg-config --cflags Qt5Core Qt5Widgets 2>/dev/null)
    QTLDLIBS = $(shell $(PKG_CONFIG_ENV) pkg-config --libs Qt5Core Qt5Widgets 2>/dev/null)
    MOC = $(shell $(PKG_CONFIG_ENV) pkg-config --variable=host_bins Qt5Core)/moc
    UIC = $(shell $(PKG_CONFIG_ENV) pkg-config --variable=host_bins Qt5Core)/uic
    ifeq ($(QTINCLUDES), )
    # if Qt5 not found check for correctly configured Qt4
        QTINCLUDES = $(shell $(PKG_CONFIG_ENV) pkg-config --cflags QtCore QtGui 2>/dev/null)
        QTLDLIBS = $(shell $(PKG_CONFIG_ENV) pkg-config --libs QtCore QtGui 2>/dev/null)
        MOC = $(shell $(PKG_CONFIG_ENV) pkg-config --variable=moc_location QtCore)
        UIC = $(shell $(PKG_CONFIG_ENV) pkg-config --variable=uic_location QtCore)
    else
        # On OSX Qt5 is claiming for a C++11 compiler (gnu++14 works too, but if nothing it fails)
        PM3CXXFLAGS += -fPIC -std=c++11
    endif
    ifeq ($(QTINCLUDES), )
    # if both pkg-config commands failed, search in common places
        ifneq ($(QTDIR), )
            QTINCLUDES = -I$(QTDIR)/include -I$(QTDIR)/include/QtCore -I$(QTDIR)/include/QtGui
            QTLDLIBS = -L$(QTDIR)/lib -lQtCore4 -lQtGui4
            ifneq ($(wildcard $(QTDIR)/include/QtWidgets),)
                QTINCLUDES += -I$(QTDIR)/include/QtWidgets
                QTLDLIBS = -L$(QTDIR)/lib -lQt5Widgets -lQt5Gui -lQt5Core
                PM3CXXFLAGS += -fPIC -std=c++11
            endif
            MOC = $(QTDIR)/bin/moc
            UIC = $(QTDIR)/bin/uic
        endif
    endif
endif

ifneq ($(QTLDLIBS),)
    QTGUISRCS = proxgui.cpp proxguiqt.cpp proxguiqt.moc.cpp
    QTGUIOBJS = $(OBJDIR)/proxgui.o $(OBJDIR)/proxguiqt.o $(OBJDIR)/proxguiqt.moc.o
    PM3CFLAGS += -DHAVE_GUI
    PM3CXXFLAGS += -DQT_NO_DEBUG
else
    QTGUISRCS = guidummy.cpp
    QTGUIOBJS = $(OBJDIR)/guidummy.o
endif

$(info ===================================================================)
$(info Client platform:   $(platform))
ifeq ($(SKIPQT),1)
$(info GUI support:       skipped)
else ifneq ($(QTLDLIBS),)
$(info GUI support:       QT found, enabled)
else
$(info GUI support:       QT not found, disabled)
endif
ifeq ($(SKIPBT),1)
$(info native BT support: skipped)
else ifneq ($(BTLDLIBS),)
$(info native BT support: Bluez found, enabled)
else
$(info native BT support: Bluez not found, disabled)
endif
$(info ===================================================================)

# Flags to generate temporary dependency files
DEPFLAGS = -MT $@ -MMD -MP -MF $(OBJDIR)/$*.Td
# make temporary to final dependency files after successful compilation
POSTCOMPILE = $(MV) -f $(OBJDIR)/$*.Td $(OBJDIR)/$*.d && $(TOUCH) $@

CORESRCS =  uart/uart_posix.c \
            uart/uart_win32.c \
            ui.c \
            commonutil.c \
            util.c \
            util_posix.c \
            scandir.c \
            crc16.c \
            crc32.c \
            comms.c

CMDSRCS =   crapto1/crapto1.c \
            crapto1/crypto1.c \
            mifare/mifaredefault.c \
            mifare/mfkey.c \
            tea.c \
            fido/additional_ca.c \
            fido/cose.c \
            fido/cbortools.c \
            fido/fidocore.c \
            crypto/asn1dump.c \
            crypto/libpcrypto.c\
            crypto/asn1utils.c\
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
            generator.c \
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
            mifare/desfire_crypto.c \
            cmdanalyse.c \
            cmdhf.c \
            cmdhflist.c \
            aidsearch.c \
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
            cmdhfmfdes.c \
            cmdhftopaz.c \
            cmdhffido.c \
            cmdhffelica.c \
            cmdhfthinfilm.c \
            cmdhfcryptorf.c \
            cmdhflto.c \
            cmdhw.c \
            cmdlf.c \
            cmdlfawid.c \
            cmdlfcotag.c \
            cmdlfem4x.c \
            cmdlffdx.c \
            cmdlfguard.c \
            cmdlfgallagher.c \
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
            cmdlfmotorola.c \
            cmdtrace.c \
            cmdflashmem.c \
            cmdflashmemspiffs.c \
            cmdsmartcard.c \
            cmdusart.c \
            cmdwiegand.c \
            cmdparser.c \
            cmdmain.c \
            pm3_binlib.c \
            scripting.c \
            cmdscript.c \
            pm3_bitlib.c \
            cmdcrc.c \
            bucketsort.c \
            flash.c \
            wiegand_formats.c \
            wiegand_formatutils.c \
            cardhelper.c \
            preferences.c



COREOBJS = $(CORESRCS:%.c=$(OBJDIR)/%.o)
CMDOBJS = $(CMDSRCS:%.c=$(OBJDIR)/%.o)
OBJCOBJS = $(OBJCSRCS:%.m=$(OBJDIR)/%.o)

BINS = proxmark3
CLEAN = $(BINS) src/*.moc.cpp src/ui/ui_overlays.h lualibs/pm3_cmd.lua lualibs/mfc_default_keys.lua
# transition: cleaning also old path stuff
CLEAN += flasher *.moc.cpp ui/ui_overlays.h

# need to assign dependancies to build these first...
all: $(BINS)

all-static: LDLIBS:=-static $(LDLIBS)
all-static: $(BINS)

proxmark3: LDLIBS+=$(LUALIB) $(JANSSONLIB) $(MBEDTLSLIB) $(CBORLIB) $(ZLIB) $(REVENGLIB) $(AMIIBOLIB) $(HARDNESTEDLIB) $(CLIPARSERLIB) $(BTLDLIBS) $(QTLDLIBS)
proxmark3: $(OBJDIR)/proxmark3.o $(COREOBJS) $(CMDOBJS) $(OBJCOBJS) $(QTGUIOBJS) liblua jansson tinycbor reveng mbedtls zlib amiibo hardnested cliparser lualibs/pm3_cmd.lua lualibs/mfc_default_keys.lua
	$(info [=] LD $@)
	$(Q)$(LD) $(LDFLAGS) $(OBJDIR)/proxmark3.o $(COREOBJS) $(CMDOBJS) $(OBJCOBJS) $(QTGUIOBJS) $(LDLIBS)  -o $@

src/proxgui.cpp: src/ui/ui_overlays.h

src/proxguiqt.moc.cpp: src/proxguiqt.h
	$(info [-] MOC $@)
	$(Q)$(MOC) -o$@ $^

src/ui/ui_overlays.h: src/ui/overlays.ui
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
	$(Q)$(MAKE) --no-print-directory -C $(AMIIBOLIBPATH) clean
	$(Q)$(MAKE) --no-print-directory -C $(HARDNESTEDPATH) clean
	$(Q)$(MAKE) --no-print-directory -C $(CLIPARSERPATH) clean

install: all
	$(info [@] Installing client to $(DESTDIR)$(PREFIX)...)
ifneq (,$(INSTALLBIN))
	    $(Q)$(MKDIR) $(DESTDIR)$(PREFIX)$(PATHSEP)$(INSTALLBINRELPATH)
	    $(Q)$(CP) $(INSTALLBIN) $(DESTDIR)$(PREFIX)$(PATHSEP)$(INSTALLBINRELPATH)
endif
ifneq (,$(INSTALLSHARE))
	    $(Q)$(MKDIR) $(DESTDIR)$(PREFIX)$(PATHSEP)$(INSTALLSHARERELPATH)
	    $(Q)$(CP) $(INSTALLSHARE) $(DESTDIR)$(PREFIX)$(PATHSEP)$(INSTALLSHARERELPATH)
endif
	@true

uninstall:
	$(info [@] Uninstalling client from $(DESTDIR)$(PREFIX)...)
ifneq (,$(INSTALLBIN))
	    $(Q)$(RM) $(foreach tool,$(INSTALLBIN),$(DESTDIR)$(PREFIX)$(PATHSEP)$(INSTALLBINRELPATH)$(PATHSEP)$(notdir $(tool)))
endif
ifneq (,$(INSTALLSHARE))
	    $(Q)$(RMDIR) $(foreach tool,$(INSTALLSHARE),$(DESTDIR)$(PREFIX)$(PATHSEP)$(INSTALLSHARERELPATH)$(PATHSEP)$(notdir $(tool)))
endif
	@true

tarbin: $(BINS)
	$(info [=] TAR ../proxmark3-$(platform)-bin.tar)
	$(Q)$(TAR) $(TARFLAGS) ../proxmark3-$(platform)-bin.tar $(BINS:%=client/%) $(WINBINS:%=client/%)

# local libraries:
liblua:
	$(info [*] MAKE $@ for $(LUAPLATFORM))
	$(Q)$(MAKE) --no-print-directory -C $(LUALIBPATH) $(LUAPLATFORM)

jansson:
	$(info [*] MAKE $@)
	$(Q)$(MAKE) --no-print-directory -C $(JANSSONLIBPATH) all

tinycbor:
	$(info [*] MAKE $@)
	$(Q)$(MAKE) --no-print-directory -C $(CBORLIBPATH) all

reveng:
	$(info [*] MAKE $@)
	$(Q)$(MAKE) --no-print-directory -C $(REVENGPATH) all

hardnested:
	$(info [*] MAKE $@)
	$(Q)$(MAKE) --no-print-directory -C $(HARDNESTEDPATH) all

amiibo:
	$(info [*] MAKE $@)
	$(Q)$(MAKE) --no-print-directory -C $(AMIIBOLIBPATH) all

cliparser:
	$(info [*] MAKE $@)
	$(Q)$(MAKE) --no-print-directory -C $(CLIPARSERPATH) all

# common libraries:
mbedtls:
	$(info [*] MAKE $@)
	$(Q)$(MAKE) --no-print-directory -C $(MBEDTLSLIBPATH) OBJDIR=$(ROOT_DIR)$(OBJDIR) BINDIR=$(ROOT_DIR)$(OBJDIR) all

zlib:
	$(info [*] MAKE $@)
	$(Q)$(MAKE) --no-print-directory -C $(ZLIBPATH) OBJDIR=$(ROOT_DIR)$(OBJDIR) BINDIR=$(ROOT_DIR)$(OBJDIR) all

.PHONY: all clean install uninstall tarbin liblua jansson tinycbor reveng hardnested amiibo cliparser mbedtls zlib

# easy printing of MAKE VARIABLES
print-%: ; @echo $* = $($*)

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

DEPENDENCY_FILES = $(patsubst %.c, $(OBJDIR)/%.d, $(CORESRCS) $(CMDSRCS)) \
	$(patsubst %.cpp, $(OBJDIR)/%.d, $(QTGUISRCS)) \
	$(patsubst %.m, $(OBJDIR)/%.d, $(OBJCSRCS)) \
	$(OBJDIR)/proxmark3.d

$(DEPENDENCY_FILES): ;
.PRECIOUS: $(DEPENDENCY_FILES)

-include $(DEPENDENCY_FILES)
