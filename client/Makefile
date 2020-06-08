#-----------------------------------------------------------------------------
# This code is licensed to you under the terms of the GNU GPL, version 2 or,
# at your option, any later version. See the LICENSE.txt file for the text of
# the license.
#-----------------------------------------------------------------------------

# Must be called before any Makefile include
ROOT_DIR:=$(dir $(realpath $(lastword $(MAKEFILE_LIST))))

include ../Makefile.defs

INSTALLBIN = proxmark3
INSTALLSHARE = cmdscripts lualibs luascripts pyscripts resources dictionaries

VPATH =  ../common src
vpath %.dic dictionaries
OBJDIR = obj

ifeq ($(platform),Darwin)
    # cf brew info qt: qt not symlinked anymore
    PKG_CONFIG_ENV := PKG_CONFIG_PATH=/usr/local/opt/qt/lib/pkgconfig
endif

###################
# local libraries #
###################

## Amiibo
AMIIBOLIBPATH = ./deps/amiitool
AMIIBOLIBINC = -I$(AMIIBOLIBPATH)
AMIIBOLIB = $(AMIIBOLIBPATH)/libamiibo.a

## Cliparser / Argtable3
CLIPARSERLIBPATH = ./deps/cliparser
CLIPARSERLIBINC = -I$(CLIPARSERLIBPATH)
CLIPARSERLIB = $(CLIPARSERLIBPATH)/libcliparser.a

## Hardnested
HARDNESTEDLIBPATH = ./deps/hardnested
HARDNESTEDLIBINC = -I$(HARDNESTEDLIBPATH)
HARDNESTEDLIB = $(HARDNESTEDLIBPATH)/libhardnested.a

## Jansson
JANSSONLIBPATH = ./deps/jansson
JANSSONLIBINC = -I$(JANSSONLIBPATH)
JANSSONLIB = $(JANSSONLIBPATH)/libjansson.a

## Lua
LUALIBPATH = ./deps/liblua
LUALIBINC = -I$(LUALIBPATH)
LUALIB = $(LUALIBPATH)/liblua.a
LUAPLATFORM = generic
ifneq (,$(findstring MINGW,$(platform)))
    LUAPLATFORM = mingw
else
    ifeq ($(platform),Darwin)
        LUAPLATFORM = macosx
    else
        LUALIB +=  -ldl
        LUAPLATFORM = linux
    endif
endif

## Reveng
REVENGLIBPATH = ./deps/reveng
REVENGLIBINC = -I$(REVENGLIBPATH)
REVENGLIB = $(REVENGLIBPATH)/libreveng.a

## Tinycbor
TINYCBORLIBPATH = ./deps/tinycbor
TINYCBORLIBINC = -I$(TINYCBORLIBPATH)
TINYCBORLIB = $(TINYCBORLIBPATH)/tinycbor.a

## Whereami
WHEREAMILIBPATH = ./deps/whereami
WHEREAMILIBINC = -I$(WHEREAMILIBPATH)
WHEREAMILIB = $(WHEREAMILIBPATH)/libwhereami.a

##########################
# common local libraries #
##########################

## mbed TLS
MBEDTLSLIBPATH = ../common/mbedtls
MBEDTLSLIBINC = -I$(MBEDTLSLIBPATH)
MBEDTLSLIB = $(OBJDIR)/libmbedtls.a

########################################################
# optional system libraries to replace local libraries #
########################################################

## Amiibo
# not distributed as system library
LDLIBS += $(AMIIBOLIB)
INCLUDES += $(AMIIBOLIBINC)

## Cliparser / Argtable3
# not distributed as system library
LDLIBS += $(CLIPARSERLIB)
INCLUDES += $(CLIPARSERLIBINC)

## Hardnested
# not distributed as system library
LDLIBS += $(HARDNESTEDLIB)
INCLUDES += $(HARDNESTEDLIBINC)

## Jansson
ifneq ($(SKIPJANSSONSYSTEM),1)
    JANSSONINCLUDES = $(shell $(PKG_CONFIG_ENV) pkg-config --cflags jansson 2>/dev/null)
    JANSSONLDLIBS = $(shell $(PKG_CONFIG_ENV) pkg-config --libs jansson 2>/dev/null)
    ifneq ($(JANSSONLDLIBS),)
        JANSSONLIB = $(JANSSONLDLIBS)
        JANSSONLIBINC = $(JANSSONINCLUDES)
        JANSSON_FOUND = 1
    endif
endif
LDLIBS += $(JANSSONLIB)
INCLUDES += $(JANSSONLIBINC)

## Lua
ifneq ($(SKIPLUASYSTEM),1)
    LUAINCLUDES = $(shell $(PKG_CONFIG_ENV) pkg-config --cflags lua5.2 2>/dev/null)
    LUALDLIBS = $(shell $(PKG_CONFIG_ENV) pkg-config --libs lua5.2 2>/dev/null)
    ifneq ($(LUALDLIBS),)
        LUALIB = $(LUALDLIBS)
        LUALIBINC = $(LUAINCLUDES)
        LUA_FOUND = 1
    endif
endif
LDLIBS += $(LUALIB)
INCLUDES += $(LUALIBINC)

## mbed TLS
# system library cannot be used because it is compiled by default without CMAC support
LDLIBS +=$(MBEDTLSLIB)
INCLUDES += $(MBEDTLSLIBINC)

## Reveng
# not distributed as system library
LDLIBS += $(REVENGLIB)
INCLUDES += $(REVENGLIBINC)

## Tinycbor
# not distributed as system library
LDLIBS += $(TINYCBORLIB)
INCLUDES += $(TINYCBORLIBINC)

## Whereami
ifneq ($(SKIPWHEREAMISYSTEM),1)
    ifneq (,$(wildcard /usr/include/whereami.h))
        WHEREAMILIB = -lwhereami
        WHEREAMILIBINC =
        WHEREAMI_FOUND = 1
    endif
endif
LDLIBS += $(WHEREAMILIB)
INCLUDES += $(WHEREAMILIBINC)

####################
# system libraries #
####################

## Atomic
# RPi Zero gcc requires -latomic
# but MacOSX /Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/ld
# doesn't recognize option --as-needed
ifneq ($(platform),Darwin)
    LDLIBS += -Wl,--as-needed -latomic -Wl,--no-as-needed
endif

## BZIP2
LDLIBS += -lbz2

## Bluez (optional)
ifneq ($(SKIPBT),1)
    BTINCLUDES = $(shell $(PKG_CONFIG_ENV) pkg-config --cflags bluez 2>/dev/null)
    BTLDLIBS = $(shell $(PKG_CONFIG_ENV) pkg-config --libs bluez 2>/dev/null)
    ifneq ($(BTLDLIBS),)
        BTLIB = $(BTLDLIBS)
        BTLIBINC = $(BTINCLUDES)
        BT_FOUND = 1
    endif
endif
LDLIBS += $(BTLIB)
INCLUDES += $(BTLIBINC)

## Math
LDLIBS += -lm

## Pthread
# Some have no pthread, e.g. termux
ifneq ($(SKIPPTHREAD),1)
    LDLIBS += -lpthread
endif

## Python3 (optional)
ifneq ($(SKIPPYTHON),1)
    PYTHONINCLUDES = $(shell $(PKG_CONFIG_ENV) pkg-config --cflags python3 2>/dev/null)
    PYTHONLDLIBS = $(shell $(PKG_CONFIG_ENV) pkg-config --libs python3 2>/dev/null)
    ifneq ($(PYTHONLDLIBS),)
        PYTHONLIB = $(PYTHONLDLIBS)
        PYTHONLIBINC = $(PYTHONINCLUDES)
        PYTHON_FOUND = 1
    else
        # since python3.8, applications willing to embed python must use -embed:
        PYTHONINCLUDES = $(shell $(PKG_CONFIG_ENV) pkg-config --cflags python3-embed 2>/dev/null)
        PYTHONLDLIBS = $(shell $(PKG_CONFIG_ENV) pkg-config --libs python3-embed 2>/dev/null)
        ifneq ($(PYTHONLDLIBS),)
            PYTHONLIB = $(PYTHONLDLIBS)
            PYTHONLIBINC = $(PYTHONINCLUDES)
            PYTHON_FOUND = 1
        endif
    endif
endif
LDLIBS += $(PYTHONLIB)
INCLUDES += $(PYTHONLIBINC)

## QT5 (or QT4 fallback) (optional)
ifneq ($(SKIPQT),1)
    # Check for correctly configured Qt5
    QTINCLUDES = $(shell $(PKG_CONFIG_ENV) pkg-config --cflags Qt5Core Qt5Widgets 2>/dev/null)
    QTLDLIBS = $(shell $(PKG_CONFIG_ENV) pkg-config --libs Qt5Core Qt5Widgets 2>/dev/null)
    MOC = $(shell $(PKG_CONFIG_ENV) pkg-config --variable=host_bins Qt5Core)/moc
    UIC = $(shell $(PKG_CONFIG_ENV) pkg-config --variable=host_bins Qt5Core)/uic
    ifneq ($(QTLDLIBS),)
        QT5_FOUND = 1
    else
        # if Qt5 not found check for correctly configured Qt4
        QTINCLUDES = $(shell $(PKG_CONFIG_ENV) pkg-config --cflags QtCore QtGui 2>/dev/null)
        QTLDLIBS = $(shell $(PKG_CONFIG_ENV) pkg-config --libs QtCore QtGui 2>/dev/null)
        MOC = $(shell $(PKG_CONFIG_ENV) pkg-config --variable=moc_location QtCore)
        UIC = $(shell $(PKG_CONFIG_ENV) pkg-config --variable=uic_location QtCore)
    endif
    ifeq ($(QTLDLIBS),)
        # if both pkg-config commands failed, search in common places
        ifneq ($(QTDIR),)
            ifneq ($(wildcard $(QTDIR)/include/QtWidgets),)
                # QT5
                QTINCLUDES = -I$(QTDIR)/include -I$(QTDIR)/include/QtCore -I$(QTDIR)/include/QtGui -I$(QTDIR)/include/QtWidgets
                QTLDLIBS = -L$(QTDIR)/lib -lQt5Core -lQt5Gui -lQt5Widgets
                QT5_FOUND = 1
            else
                # QT4
                QTINCLUDES = -I$(QTDIR)/include -I$(QTDIR)/include/QtCore -I$(QTDIR)/include/QtGui
                QTLDLIBS = -L$(QTDIR)/lib -lQtCore4 -lQtGui4
            endif
            MOC = $(QTDIR)/bin/moc
            UIC = $(QTDIR)/bin/uic
        endif
    endif
    ifneq ($(QTLDLIBS),)
        QT_FOUND = 1
    endif
endif
LDLIBS += $(QTLDLIBS)
CXXINCLUDES += $(QTINCLUDES)

## Readline
ifneq ($(SKIPREADLINE),1)
    ifeq ($(platform),Darwin)
        LDLIBS += -L/usr/local/opt/readline/lib
        INCLUDES += -I/usr/local/opt/readline/include
    endif
    LDLIBS += -lreadline
    READLINE_FOUND = 1
endif

#######################################################################################################
CFLAGS ?= $(DEFCFLAGS)
# We cannot just use CFLAGS+=... because it has impact on sub-makes if CFLAGS is defined in env:
PM3CFLAGS = $(CFLAGS)
PM3CFLAGS += -I./src -I../include -I../common -I../common_fpga $(INCLUDES)
# WIP Testing
#PM3CFLAGS += -std=c11 -pedantic

PREFIX ?= /usr/local
ifneq (,$(findstring MINGW,$(platform)))
    # Mingw uses by default Microsoft printf, we want the GNU printf (e.g. for %z)
    # and setting _ISOC99_SOURCE sets internally __USE_MINGW_ANSI_STDIO=1
    # FTR __USE_MINGW_ANSI_STDIO seems deprecated in Mingw32
    # but not Mingw64 https://fr.osdn.net/projects/mingw/lists/archive/users/2019-January/000199.html
    PM3CFLAGS += -D_ISOC99_SOURCE
    PM3CFLAGS += -mno-ms-bitfields -fexec-charset=cp850
endif

ifeq ($(READLINE_FOUND),1)
    PM3CFLAGS += -DHAVE_READLINE
endif

ifeq ($(BT_FOUND),1)
    PM3CFLAGS += -DHAVE_BLUEZ
endif

ifeq ($(PYTHON_FOUND),1)
    PM3CFLAGS += -DHAVE_PYTHON
endif


CXXFLAGS ?= -Wall -Werror -O3
PM3CXXFLAGS = $(CXXFLAGS)
PM3CXXFLAGS += -I../include

ifeq ($(QT_FOUND),1)
    PM3CFLAGS += -DHAVE_GUI
    PM3CXXFLAGS += -DQT_NO_DEBUG
    ifeq ($(QT5_FOUND),1)
        # On OSX Qt5 is claiming for a C++11 compiler (gnu++14 works too, but if nothing it fails)
        PM3CXXFLAGS += -fPIC -std=c++11
    endif
endif

PM3LDFLAGS = $(LDFLAGS)
ifeq ($(platform),Darwin)
    PM3LDFLAGS += -framework Foundation -framework AppKit
endif

###################
# printing status #
###################

$(info ===================================================================)
$(info Client platform:   $(platform))

ifeq ($(SKIPQT),1)
    $(info GUI support:       skipped)
else
    ifeq ($(QT_FOUND),1)
        ifeq ($(QT5_FOUND),1)
            $(info GUI support:       QT5 found, enabled)
        else
            $(info GUI support:       QT4 found, enabled)
        endif
    else
        $(info GUI support:       QT not found, disabled)
    endif
endif

ifeq ($(SKIPBT),1)
    $(info native BT support: skipped)
else
    ifeq ($(BT_FOUND),1)
        $(info native BT support: Bluez found, enabled)
    else
        $(info native BT support: Bluez not found, disabled)
    endif
endif

ifeq ($(SKIPJANSSONSYSTEM),1)
    $(info Jansson library:   local library forced)
else ifeq ($(JANSSON_FOUND),1)
    $(info Jansson library:   system library found)
else
    $(info Jansson library:   system library not found, using local library)
endif

ifeq ($(SKIPLUASYSTEM),1)
    $(info Lua library:       local library forced)
else
    ifeq ($(LUA_FOUND),1)
        $(info Lua library:       system library found)
    else
        $(info Lua library:       system library not found, using local library)
    endif
endif

ifeq ($(SKIPPYTHON),1)
        $(info Python3 library:   skipped)
else
    ifeq ($(PYTHON_FOUND),1)
        $(info Python3 library:   Python3 v$(shell pkg-config --modversion python3) found, enabled)
    else
        $(info Python3 library:   Python3 not found, disabled)
    endif
endif

ifeq ($(SKIPREADLINE),1)
    $(info Readline library:  skipped)
else
    ifeq ($(READLINE_FOUND),1)
        $(info Readline library:  enabled)
    else
        $(info Readline library:  Readline not found, disabled)
    endif
endif

ifeq ($(SKIPWHEREAMISYSTEM),1)
    $(info Whereami library:  local library forced)
else
    ifeq ($(WHEREAMI_FOUND),1)
        $(info Whereami library:  system library found)
    else
        $(info Whereami library:  system library not found, using local library)
    endif
endif

$(info compiler version:  $(shell $(CC) --version|head -n 1))
$(info ===================================================================)

################
# dependencies #
################

# Flags to generate temporary dependency files
DEPFLAGS = -MT $@ -MMD -MP -MF $(OBJDIR)/$*.Td
# make temporary to final dependency files after successful compilation
POSTCOMPILE = $(MV) -f $(OBJDIR)/$*.Td $(OBJDIR)/$*.d && $(TOUCH) $@

################
# enumerations #
################

SRCS =  aidsearch.c \
		cmdanalyse.c \
		cmdcrc.c \
		cmddata.c \
		cmdflashmem.c \
		cmdflashmemspiffs.c \
		cmdhf.c \
		cmdhf14a.c \
		cmdhf14b.c \
		cmdhf15.c \
		cmdhfcryptorf.c \
		cmdhfepa.c \
		cmdhffelica.c \
		cmdhffido.c \
		cmdhficlass.c \
		cmdhflegic.c \
		cmdhflist.c \
		cmdhflto.c \
		cmdhfmf.c \
		cmdhfmfdes.c \
		cmdhfmfhard.c \
		cmdhfmfu.c \
		cmdhfmfp.c \
		cmdhfthinfilm.c \
		cmdhftopaz.c \
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
		cmdlfindala.c \
		cmdlfio.c \
		cmdlfjablotron.c \
		cmdlfkeri.c \
		cmdlfmotorola.c \
		cmdlfnedap.c \
		cmdlfnexwatch.c \
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
		cmdmain.c \
		cmdparser.c \
		cmdscript.c \
		cmdsmartcard.c \
		cmdtrace.c \
		cmdusart.c \
		cmdwiegand.c \
		comms.c \
		crypto/asn1dump.c \
		crypto/asn1utils.c\
		crypto/libpcrypto.c\
		emv/apduinfo.c \
		emv/cmdemv.c \
		emv/crypto.c\
		emv/crypto_polarssl.c\
		emv/dol.c \
		emv/dump.c \
		emv/emv_pk.c\
		emv/emv_pki.c\
		emv/emv_pki_priv.c\
		emv/emv_roca.c \
		emv/emv_tags.c \
		emv/emvcore.c \
		emv/emvjson.c\
		emv/tlv.c \
		emv/test/crypto_test.c\
		emv/test/cryptotest.c\
		emv/test/cda_test.c\
		emv/test/dda_test.c\
		emv/test/sda_test.c\
		fido/additional_ca.c \
		fido/cose.c \
		fido/cbortools.c \
		fido/fidocore.c \
		fileutils.c \
		flash.c \
		generator.c \
		graph.c \
		jansson_path.c \
		loclass/cipher.c \
		loclass/cipherutils.c \
		loclass/elite_crack.c \
		loclass/ikeys.c \
		mifare/desfire_crypto.c \
		mifare/mad.c \
		mifare/mfkey.c \
		mifare/mifare4.c \
		mifare/mifaredefault.c \
		mifare/mifarehost.c \
		mifare/ndef.c \
		pm3_binlib.c \
		pm3_bitlib.c \
		preferences.c \
		prng.c \
		proxmark3.c \
		scandir.c \
		uart/uart_posix.c \
		uart/uart_win32.c \
		scripting.c \
		tea.c \
		ui.c \
		util.c \
		version.c \
		wiegand_formats.c \
		wiegand_formatutils.c

# common
SRCS += bucketsort.c \
		cardhelper.c \
		crapto1/crapto1.c \
		crapto1/crypto1.c \
		crc.c \
		crc16.c \
		crc32.c \
		crc64.c \
		commonutil.c \
		iso15693tools.c \
		legic_prng.c \
		lfdemod.c \
		parity.c \
		util_posix.c

# gui
ifeq ($(QT_FOUND),1)
    CXXSRCS = proxgui.cpp proxguiqt.cpp proxguiqt.moc.cpp
else
    CXXSRCS = guidummy.cpp
endif

# OS X
ifeq ($(platform),Darwin)
    OBJCSRCS = util_darwin.m
endif

OBJS = $(SRCS:%.c=$(OBJDIR)/%.o)
OBJS += $(CXXSRCS:%.cpp=$(OBJDIR)/%.o)
OBJS += $(OBJCSRCS:%.m=$(OBJDIR)/%.o)

BINS = proxmark3

CLEAN = $(BINS) src/version.c src/*.moc.cpp src/ui/ui_overlays.h lualibs/pm3_cmd.lua lualibs/mfc_default_keys.lua
# transition: cleaning also old path stuff
CLEAN += flasher *.moc.cpp ui/ui_overlays.h

###########
# targets #
###########

# need to assign dependancies to build these first...
all: $(BINS)

all-static: LDLIBS:=-static $(LDLIBS)
all-static: $(BINS)

proxmark3: $(OBJS) amiibo cliparser jansson hardnested lua mbedtls reveng tinycbor whereami lualibs/pm3_cmd.lua lualibs/mfc_default_keys.lua
	$(info [=] LD $@)
	$(Q)$(LD) $(PM3LDFLAGS) $(OBJS) $(LDLIBS) -o $@

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
	$(Q)$(MAKE) --no-print-directory -C $(AMIIBOLIBPATH) clean
	$(Q)$(MAKE) --no-print-directory -C $(CLIPARSERLIBPATH) clean
	$(Q)$(MAKE) --no-print-directory -C $(HARDNESTEDLIBPATH) clean
	$(Q)$(MAKE) --no-print-directory -C $(JANSSONLIBPATH) clean
	$(Q)$(MAKE) --no-print-directory -C $(LUALIBPATH) clean
	$(Q)$(MAKE) --no-print-directory -C $(REVENGLIBPATH) clean
	$(Q)$(MAKE) --no-print-directory -C $(TINYCBORLIBPATH) clean
	$(Q)$(MAKE) --no-print-directory -C $(WHEREAMILIBPATH) clean
	@# Just in case someone compiled within these dirs:
	$(Q)$(MAKE) --no-print-directory -C $(MBEDTLSLIBPATH) clean

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

###########################
# local libraries targets #
###########################

amiibo:
	$(info [*] MAKE $@)
	$(Q)$(MAKE) --no-print-directory -C $(AMIIBOLIBPATH) all

cliparser:
	$(info [*] MAKE $@)
	$(Q)$(MAKE) --no-print-directory -C $(CLIPARSERLIBPATH) all

hardnested:
	$(info [*] MAKE $@)
	$(Q)$(MAKE) --no-print-directory -C $(HARDNESTEDLIBPATH) all

jansson:
ifneq ($(JANSSON_FOUND),1)
	$(info [*] MAKE $@)
	$(Q)$(MAKE) --no-print-directory -C $(JANSSONLIBPATH) all
endif

lua:
ifneq ($(LUA_FOUND),1)
	$(info [*] MAKE $@ for $(LUAPLATFORM))
	$(Q)$(MAKE) --no-print-directory -C $(LUALIBPATH) $(LUAPLATFORM)
endif

mbedtls:
	$(info [*] MAKE $@)
	$(Q)$(MAKE) --no-print-directory -C $(MBEDTLSLIBPATH) OBJDIR=$(ROOT_DIR)$(OBJDIR) BINDIR=$(ROOT_DIR)$(OBJDIR) all

reveng:
	$(info [*] MAKE $@)
	$(Q)$(MAKE) --no-print-directory -C $(REVENGLIBPATH) all

tinycbor:
	$(info [*] MAKE $@)
	$(Q)$(MAKE) --no-print-directory -C $(TINYCBORLIBPATH) all

whereami:
ifneq ($(WHEREAMI_FOUND),1)
	$(info [*] MAKE $@)
	$(Q)$(MAKE) --no-print-directory -C $(WHEREAMILIBPATH) all
endif

########
# misc #
########

.PHONY: all clean install uninstall tarbin amiibo cliparser hardnested jansson lua mbedtls reveng tinycbor whereami

# version.c should be remade on every compilation
src/version.c: default_version.c
	$(info [=] GEN $@)
	$(Q)$(SH) ../tools/mkversion.sh > $@ || $(PERL) ../tools/mkversion.pl > $@ || $(CP) $< $@

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
	$(Q)$(CXX) $(DEPFLAGS) $(PM3CXXFLAGS) $(CXXINCLUDES) -c -o $@ $<
	$(Q)$(POSTCOMPILE)

%.o: %.m
$(OBJDIR)/%.o : %.m $(OBJDIR)/%.d
	$(info [-] CC $<)
	$(Q)$(MKDIR) $(dir $@)
	$(Q)$(CC) $(DEPFLAGS) $(PM3CFLAGS) -c -o $@ $<
	$(Q)$(POSTCOMPILE)

DEPENDENCY_FILES = $(patsubst %.c, $(OBJDIR)/%.d, $(SRCS)) \
                   $(patsubst %.cpp, $(OBJDIR)/%.d, $(CXXSRCS)) \
                   $(patsubst %.m, $(OBJDIR)/%.d, $(OBJCSRCS))

$(DEPENDENCY_FILES): ;
.PRECIOUS: $(DEPENDENCY_FILES)

-include $(DEPENDENCY_FILES)
