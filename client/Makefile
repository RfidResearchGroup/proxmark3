#-----------------------------------------------------------------------------
# Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# See LICENSE.txt for the text of the license.
#-----------------------------------------------------------------------------

ifeq ($(PLTNAME),)
    -include ../Makefile.platform
    -include ../.Makefile.options.cache
    ifneq ($(PLATFORM), $(CACHED_PLATFORM))
        $(error platform definitions have been changed, please "make clean" at the root of the project)
    endif
endif
include ../Makefile.defs

ifeq ($(PLATFORM),PM3ICOPYX)
  INCLUDES += -DICOPYX
endif

INSTALLBIN = proxmark3
INSTALLSHARE = cmdscripts lualibs luascripts pyscripts resources dictionaries

VPATH =  ../common src
vpath %.dic dictionaries
OBJDIR = obj

ifeq ($(USE_BREW),1)
	INCLUDES += -I$(BREW_PREFIX)/include
	LDLIBS += -L$(BREW_PREFIX)/lib
	PKG_CONFIG_ENV := PKG_CONFIG_PATH=$(BREW_PREFIX)/lib/pkgconfig:$(BREW_PREFIX)/opt/qt/lib/pkgconfig:$(BREW_PREFIX)/opt/qt5/lib/pkgconfig
endif

ifeq ($(USE_MACPORTS),1)
	INCLUDES += -I$(MACPORTS_PREFIX)/include
	LDLIBS += -L$(MACPORTS_PREFIX)/lib
	PKG_CONFIG_ENV := PKG_CONFIG_PATH=$(MACPORTS_PREFIX)/lib/pkgconfig
endif


PM3INCLUDES =

###################
# local libraries #
###################

## Amiibo
AMIIBOLIBPATH = ./deps/amiitool
AMIIBOLIBINC = -I$(AMIIBOLIBPATH)
AMIIBOLIB = $(AMIIBOLIBPATH)/libamiibo.a
AMIIBOLIBLD =

## Cliparser / Argtable3
CLIPARSERLIBPATH = ./deps/cliparser
CLIPARSERLIBINC = -I$(CLIPARSERLIBPATH)
CLIPARSERLIB = $(CLIPARSERLIBPATH)/libcliparser.a
CLIPARSERLIBLD =

## Hardnested
HARDNESTEDLIBPATH = ./deps/hardnested
HARDNESTEDLIBINC = -I$(HARDNESTEDLIBPATH)
HARDNESTEDLIB = $(HARDNESTEDLIBPATH)/libhardnested.a
HARDNESTEDLIBLD =

## Jansson
JANSSONLIBPATH = ./deps/jansson
JANSSONLIBINC = -I$(JANSSONLIBPATH)
JANSSONLIB = $(JANSSONLIBPATH)/libjansson.a
JANSSONLIBLD =

## Linenoise
# Can be used if Readline is unavailable or explicitely disabled
# Requires to be unpacked, see deps/get_linenoise.sh
LINENOISELIBPATH = ./deps/linenoise
LINENOISELIBINC = -I$(LINENOISELIBPATH)
LINENOISELIB = $(LINENOISELIBPATH)/liblinenoise.a
LINENOISELIBLD =

## Lua
LUALIBPATH = ./deps/liblua
LUALIBINC = -I$(LUALIBPATH)
LUALIB = $(LUALIBPATH)/liblua.a
LUALIBLD =
LUAPLATFORM = generic
ifneq (,$(findstring MINGW,$(platform)))
    LUAPLATFORM = mingw
else
    ifeq ($(platform),Darwin)
        LUAPLATFORM = macosx
    else
        LUALIBLD +=  -ldl
        LUAPLATFORM = linux
    endif
endif

## Winsock2
ifneq (,$(findstring MINGW,$(platform)))
	LDLIBS += -lws2_32
endif

## Reveng
REVENGLIBPATH = ./deps/reveng
REVENGLIBINC = -I$(REVENGLIBPATH)
REVENGLIB = $(REVENGLIBPATH)/libreveng.a
REVENGLIBLD =

## Tinycbor
TINYCBORLIBPATH = ./deps/tinycbor
TINYCBORLIBINC = -I$(TINYCBORLIBPATH)
TINYCBORLIB = $(TINYCBORLIBPATH)/tinycbor.a
TINYCBORLIBLD =

## Whereami
WHEREAMILIBPATH = ./deps/whereami
WHEREAMILIBINC = -I$(WHEREAMILIBPATH)
WHEREAMILIB = $(WHEREAMILIBPATH)/libwhereami.a
WHEREAMILIBLD =

##########################
# common local libraries #
##########################

## mbed TLS
MBEDTLSLIBPATH = ../common/mbedtls
MBEDTLSLIBINC = -I$(MBEDTLSLIBPATH)
MBEDTLSLIB = $(OBJDIR)/libmbedtls.a
MBEDTLSLIBCLIENTRELPATH = ../../client

########################################################
# optional system libraries to replace local libraries #
########################################################

## Amiibo
# not distributed as system library
STATICLIBS += $(AMIIBOLIB)
LDLIBS += $(AMIIBOLIBLD)
PM3INCLUDES += $(AMIIBOLIBINC)

## Cliparser / Argtable3
# not distributed as system library
STATICLIBS += $(CLIPARSERLIB)
LDLIBS += $(CLIPARSERLIBLD)
PM3INCLUDES += $(CLIPARSERLIBINC)

## Hardnested
# not distributed as system library
STATICLIBS += $(HARDNESTEDLIB)
LDLIBS +=$(HARDNESTEDLIBLD)
PM3INCLUDES += $(HARDNESTEDLIBINC)

## Linenoise
# wait to see if Readline is available

## Lua
ifneq ($(SKIPLUASYSTEM),1)
    ifdef MACPORTS_PREFIX
        LUAINCLUDES = $(shell $(PKG_CONFIG_ENV) pkg-config --cflags lua-5.2 2>/dev/null)
        LUALDLIBS = $(shell $(PKG_CONFIG_ENV) pkg-config --libs lua-5.2 2>/dev/null)
    else
        LUAINCLUDES = $(shell $(PKG_CONFIG_ENV) pkg-config --cflags lua5.2 2>/dev/null)
        LUALDLIBS = $(shell $(PKG_CONFIG_ENV) pkg-config --libs lua5.2 2>/dev/null)
    endif
    ifneq ($(LUALDLIBS),)
        LUALIB =
        LUALIBLD = $(LUALDLIBS)
        LUALIBINC = $(LUAINCLUDES)
        LUA_FOUND = 1
    endif
endif
STATICLIBS += $(LUALIB)
LDLIBS += $(LUALIBLD)
PM3INCLUDES += $(LUALIBINC)

## Jansson
# Jansson section needs to be after Lua to avoid interferences on macOS if a locally incompatible Lua was available, see PR 1155
ifneq ($(SKIPJANSSONSYSTEM),1)
    JANSSONINCLUDES = $(shell $(PKG_CONFIG_ENV) pkg-config --cflags jansson 2>/dev/null)
    JANSSONLDLIBS = $(shell $(PKG_CONFIG_ENV) pkg-config --libs jansson 2>/dev/null)
    ifneq ($(JANSSONLDLIBS),)
        JANSSONLIB =
        JANSSONLIBLD = $(JANSSONLDLIBS)
        JANSSONLIBINC = $(JANSSONINCLUDES)
        JANSSON_FOUND = 1
    endif
endif
STATICLIBS += $(JANSSONLIB)
LDLIBS += $(JANSSONLIBLD)
PM3INCLUDES += $(JANSSONLIBINC)

## mbed TLS
# system library cannot be used because it is compiled by default without CMAC support
STATICLIBS += $(MBEDTLSLIB)
LDLIBS += $(MBEDTLSLIBLD)
PM3INCLUDES += $(MBEDTLSLIBINC)

## Reveng
# not distributed as system library
STATICLIBS += $(REVENGLIB)
LDLIBS += $(REVENGLIBLD)
PM3INCLUDES += $(REVENGLIBINC)

## Tinycbor
# not distributed as system library
STATICLIBS += $(TINYCBORLIB)
LDLIBS += $(TINYCBORLIBLD)
PM3INCLUDES += $(TINYCBORLIBINC)

## Whereami
ifneq ($(SKIPWHEREAMISYSTEM),1)
    ifneq (,$(wildcard /usr/include/whereami.h))
        WHEREAMILIB =
        WHEREAMILIBLD = -lwhereami
        WHEREAMILIBINC =
        WHEREAMI_FOUND = 1
    endif
endif
STATICLIBS += $(WHEREAMILIB)
LDLIBS += $(WHEREAMILIBLD)
PM3INCLUDES += $(WHEREAMILIBINC)

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

## LZ4
LDLIBS += -llz4

## Bluez (optional)
ifneq ($(SKIPBT),1)
    BTINCLUDES = $(shell $(PKG_CONFIG_ENV) pkg-config --cflags bluez 2>/dev/null)
    BTLDLIBS = $(shell $(PKG_CONFIG_ENV) pkg-config --libs bluez 2>/dev/null)
    ifneq ($(BTLDLIBS),)
        BTLIBLD = $(BTLDLIBS)
        BTLIBINC = $(BTINCLUDES)
        BT_FOUND = 1
    endif
endif
LDLIBS += $(BTLIBLD)
PM3INCLUDES += $(BTLIBINC)

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
        PYTHONLIBLD = $(PYTHONLDLIBS)
        PYTHONLIBINC = $(PYTHONINCLUDES)
        PYTHON_FOUND = 1
    else
        # since python3.8, applications willing to embed python must use -embed:
        PYTHONINCLUDES = $(shell $(PKG_CONFIG_ENV) pkg-config --cflags python3-embed 2>/dev/null)
        PYTHONLDLIBS = $(shell $(PKG_CONFIG_ENV) pkg-config --libs python3-embed 2>/dev/null)
        ifneq ($(PYTHONLDLIBS),)
            PYTHONLIBLD = $(PYTHONLDLIBS)
            PYTHONLIBINC = $(PYTHONINCLUDES)
            PYTHON_FOUND = 1
        endif
    endif
endif
LDLIBS += $(PYTHONLIBLD)
PM3INCLUDES += $(PYTHONLIBINC)

## QT5 (or QT4 fallback) (optional)
ifneq ($(SKIPQT),1)
    # Check for correctly configured Qt5
    QTINCLUDES = $(shell $(PKG_CONFIG_ENV) pkg-config --cflags Qt5Core Qt5Widgets 2>/dev/null)
    QTLDLIBS = $(shell $(PKG_CONFIG_ENV) pkg-config --libs Qt5Core Qt5Widgets 2>/dev/null)
    MOC = $(shell $(PKG_CONFIG_ENV) pkg-config --variable=host_bins Qt5Core)/moc
    UIC = $(shell $(PKG_CONFIG_ENV) pkg-config --variable=host_bins Qt5Core)/uic
    QMAKE = $(shell $(PKG_CONFIG_ENV) pkg-config --variable=host_bins Qt5Core)/qmake
    ifneq ($(QTLDLIBS),)
        QT5_FOUND = 1
    else
        # if Qt5 not found check for correctly configured Qt4
        QTINCLUDES = $(shell $(PKG_CONFIG_ENV) pkg-config --cflags QtCore QtGui 2>/dev/null)
        QTLDLIBS = $(shell $(PKG_CONFIG_ENV) pkg-config --libs QtCore QtGui 2>/dev/null)
        MOC = $(shell $(PKG_CONFIG_ENV) pkg-config --variable=moc_location QtCore)
        UIC = $(shell $(PKG_CONFIG_ENV) pkg-config --variable=uic_location QtCore)
        QMAKE = $(shell $(PKG_CONFIG_ENV) pkg-config --variable=exec_prefix QtCore)/bin/qmake
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
            QMAKE = $(QTDIR)/bin/qmake
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
    ifeq ($(USE_BREW),1)
        LDLIBS += -L$(BREW_PREFIX)/opt/readline/lib
        PM3INCLUDES += -I$(BREW_PREFIX)/opt/readline/include
    endif

    ifeq ($(USE_MACPORTS),1)
        PM3INCLUDES += -I$(MACPORTS_PREFIX)/include/readline
    endif

    LDLIBS += -lreadline
    READLINE_FOUND = 1
else
## Linenoise
    ifneq ($(SKIPLINENOISE),1)
        ifneq (,$(wildcard $(LINENOISELIBPATH)))
            STATICLIBS += $(LINENOISELIB)
            LDLIBS += $(LINENOISELIBLD)
            PM3INCLUDES += $(LINENOISELIBINC)
            LINENOISE_LOCAL_FOUND = 1
		endif
    endif
endif

########
# SWIG #
########

ifneq ("$(wildcard src/pm3_luawrap.c)","")
    SWIG_LUA_FOUND = 1
endif
ifeq ($(PYTHON_FOUND),1)
    ifneq ("$(wildcard src/pm3_pywrap.c)","")
        SWIG_PYTHON_FOUND = 1
    endif
endif

#######################################################################################################
CFLAGS ?= $(DEFCFLAGS)
CFLAGS += $(MYDEFS) $(MYCFLAGS) $(MYINCLUDES)

# We cannot just use CFLAGS+=... because it has impact on sub-makes if CFLAGS is defined in env:
PM3CFLAGS = $(CFLAGS)
PM3CFLAGS += -g -I./src -I./include -I../include -I../common -I../common_fpga $(PM3INCLUDES) $(INCLUDES)
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

ifeq ($(LINENOISE_LOCAL_FOUND),1)
    PM3CFLAGS += -DHAVE_LINENOISE
endif

ifeq ($(BT_FOUND),1)
    PM3CFLAGS += -DHAVE_BLUEZ
endif

ifeq ($(PYTHON_FOUND),1)
    PM3CFLAGS += -DHAVE_PYTHON
endif

ifeq ($(SWIG_LUA_FOUND),1)
    PM3CFLAGS += -DHAVE_LUA_SWIG
endif
ifeq ($(SWIG_PYTHON_FOUND),1)
    PM3CFLAGS += -DHAVE_PYTHON_SWIG
endif

PM3CFLAGS += -DHAVE_SNPRINTF

CXXFLAGS ?= -Wall -Werror -O3
CXXFLAGS += $(MYDEFS) $(MYCXXFLAGS) $(MYINCLUDES)

PM3CXXFLAGS = $(CXXFLAGS)
PM3CXXFLAGS += -I../include -I./include

ifeq ($(QT_FOUND),1)
    PM3CFLAGS += -DHAVE_GUI
    PM3CXXFLAGS += -DQT_NO_DEBUG
    ifeq ($(QT5_FOUND),1)
        # On OSX Qt5 is claiming for a C++11 compiler (gnu++14 works too, but if nothing it fails)
        PM3CXXFLAGS += -fPIC -std=c++11
    endif
endif

PM3CXXFLAGS += -DHAVE_SNPRINTF

LDFLAGS ?= $(DEFLDFLAGS)
LDFLAGS += $(MYLDFLAGS)

PM3LDFLAGS = $(LDFLAGS)
ifeq ($(platform),Darwin)
    ifeq ($(shell uname -p),arm64)
        # The platform is iOS
        PM3LDFLAGS += -framework Foundation -framework UIKit
    else
        # M* macOS devices return arm
        PM3LDFLAGS += -framework Foundation -framework AppKit
    endif
endif

###################
# printing status #
###################

$(info ===================================================================)
$(info Version info:      $(shell ../tools/mkversion.sh --short 2>/dev/null))
$(info Client platform:   $(platform))

ifeq ($(SKIPQT),1)
    $(info GUI support:       skipped)
else
    ifeq ($(QT_FOUND),1)
        ifeq ($(QT5_FOUND),1)
            $(info GUI support:       QT5 found, enabled ($(shell QT_SELECT=5 $(QMAKE) -v 2>/dev/null|grep -o 'Qt version.*')))
        else
            $(info GUI support:       QT4 found, enabled ($(shell QT_SELECT=4 $(QMAKE) -v 2>/dev/null|grep -o 'Qt version.*')))
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
        $(info Python3 library:   Python3 v$(shell $(PKG_CONFIG_ENV) pkg-config --modversion python3) found, enabled)
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

ifneq ($(READLINE_FOUND),1)
    ifeq ($(SKIPLINENOISE),1)
        $(info Linenoise library: skipped)
    else
        ifeq ($(LINENOISE_LOCAL_FOUND),1)
            $(info Linenoise library: enabled)
        else
            $(info Linenoise library: Linenoise not found, disabled)
        endif
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

ifeq ($(SWIG_LUA_FOUND),1)
        $(info Lua SWIG:          wrapper found)
endif
ifeq ($(SWIG_PYTHON_FOUND),1)
        $(info Python SWIG:       wrapper found)
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

SRCS =  mifare/aiddesfire.c \
		aidsearch.c \
		atrs.c \
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
		cmdhfemrtd.c \
		cmdhffelica.c \
		cmdhffido.c \
		cmdhffudan.c \
		cmdhfgallagher.c \
		cmdhfksx6924.c \
		cmdhfcipurse.c \
		cmdhficlass.c \
		cmdhflegic.c \
		cmdhfjooki.c \
		cmdhflist.c \
		cmdhflto.c \
		cmdhfmf.c \
		cmdhfmfdes.c \
		cmdhfmfhard.c \
		cmdhfmfu.c \
		cmdhfmfp.c \
		cmdhfntag424.c \
		cmdhfseos.c \
		cmdhfst.c \
		cmdhfst25ta.c \
		cmdhftesla.c \
		cmdhfthinfilm.c \
		cmdhftopaz.c \
		cmdhftexkom.c \
		cmdhfvas.c \
		cmdhfwaveshare.c \
		cmdhfxerox.c \
		cmdhw.c \
		cmdlf.c \
		cmdlfawid.c \
		cmdlfcotag.c \
		cmdlfdestron.c \
		cmdlfem.c \
		cmdlfem410x.c \
		cmdlfem4x05.c \
		cmdlfem4x50.c \
		cmdlfem4x70.c \
		cmdlffdxb.c \
		cmdlfguard.c \
		cmdlfgallagher.c \
		cmdlfhid.c \
		cmdlfhitag.c \
		cmdlfidteck.c \
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
		cmdlfzx8211.c \
		cmdmain.c \
		cmdnfc.c \
		cmdparser.c \
		cmdpiv.c \
		cmdscript.c \
		cmdsmartcard.c \
		cmdtrace.c \
		cmdusart.c \
		cmdwiegand.c \
		comms.c \
		crypto/asn1dump.c \
		crypto/asn1utils.c\
		crypto/libpcrypto.c\
		emv/cmdemv.c \
		emv/crypto.c\
		emv/crypto_polarssl.c\
		emv/dol.c \
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
		ksx6924/ksx6924core.c \
		cipurse/cipursecore.c \
		cipurse/cipursecrypto.c \
		cipurse/cipursetest.c \
		fileutils.c \
		flash.c \
		generator.c \
		graph.c \
		jansson_path.c \
		iso4217.c \
		iso7816/apduinfo.c \
		iso7816/iso7816core.c \
		loclass/cipher.c \
		loclass/cipherutils.c \
		loclass/elite_crack.c \
		loclass/ikeys.c \
		mifare/lrpcrypto.c \
		mifare/desfirecrypto.c \
		mifare/desfirecore.c \
        mifare/desfiresecurechan.c \
        mifare/desfiretest.c \
		mifare/gallaghercore.c \
		mifare/mad.c \
		mifare/mfkey.c \
		mifare/mifare4.c \
		mifare/mifaredefault.c \
		mifare/mifarehost.c \
		nfc/ndef.c \
		pm3.c \
		pm3_binlib.c \
		pm3_bitlib.c \
		preferences.c \
		pm3line.c \
		proxmark3.c \
		scandir.c \
		uart/uart_posix.c \
		uart/uart_win32.c \
		scripting.c \
		ui.c \
		util.c \
		version_pm3.c \
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
		util_posix.c

# swig

SWIGSRCS =
ifeq ($(SWIG_LUA_FOUND),1)
    SWIGSRCS += pm3_luawrap.c
endif
ifeq ($(SWIG_PYTHON_FOUND),1)
    SWIGSRCS += pm3_pywrap.c
endif

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
OBJS += $(SWIGSRCS:%.c=$(OBJDIR)/%.o)
OBJS += $(CXXSRCS:%.cpp=$(OBJDIR)/%.o)
OBJS += $(OBJCSRCS:%.m=$(OBJDIR)/%.o)

BINS = proxmark3

CLEAN = $(BINS) src/version_pm3.c src/*.moc.cpp src/ui/ui_overlays.h src/ui/ui_image.h lualibs/pm3_cmd.lua lualibs/mfc_default_keys.lua
# transition: cleaning also old path stuff
CLEAN += flasher *.moc.cpp ui/ui_overlays.h ui/ui_image.h

###########
# targets #
###########

# need to assign dependancies to build these first...
all: $(BINS)

all-static: LDLIBS:=-static $(LDLIBS)
all-static: $(BINS)

proxmark3: $(OBJS) $(STATICLIBS) lualibs/pm3_cmd.lua lualibs/mfc_default_keys.lua
	$(info [=] CXX $@)
#	$(Q)$(CXX) $(PM3LDFLAGS) $(OBJS) $(STATICLIBS) $(LDLIBS) -o $@
	$(Q)$(CXX) $(PM3CFLAGS) $(PM3LDFLAGS) $(OBJS) $(STATICLIBS) $(LDLIBS) -o $@

src/proxgui.cpp: src/ui/ui_overlays.h src/ui/ui_image.h

src/proxguiqt.cpp: src/proxguiqt.h

src/proxguiqt.moc.cpp: src/proxguiqt.h
	$(info [-] MOC $@)
	$(Q)$(MOC) -o$@ $^

src/proxguiqt.h: src/ui/ui_overlays.h src/ui/ui_image.h

src/ui/ui_overlays.h: src/ui/overlays.ui
	$(info [-] UIC $@)
	$(Q)$(UIC) $^ > $@

src/ui/ui_image.h: src/ui/image.ui
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
ifeq ($(LINENOISE_LOCAL_FOUND), 1)
	$(Q)$(MAKE) --no-print-directory -C $(LINENOISELIBPATH) clean
endif
	$(Q)$(MAKE) --no-print-directory -C $(LUALIBPATH) clean
	$(Q)$(MAKE) --no-print-directory -C $(REVENGLIBPATH) clean
	$(Q)$(MAKE) --no-print-directory -C $(TINYCBORLIBPATH) clean
	$(Q)$(MAKE) --no-print-directory -C $(WHEREAMILIBPATH) clean
	@# Just in case someone compiled within these dirs:
	$(Q)$(MAKE) --no-print-directory -C $(MBEDTLSLIBPATH) clean

install: all
	$(info [@] Installing client to $(DESTDIR)$(PREFIX)...)
ifneq (,$(INSTALLBIN))
	    $(Q)$(INSTALLSUDO) $(MKDIR) $(DESTDIR)$(PREFIX)$(PATHSEP)$(INSTALLBINRELPATH)
	    $(Q)$(INSTALLSUDO) $(CP) $(INSTALLBIN) $(DESTDIR)$(PREFIX)$(PATHSEP)$(INSTALLBINRELPATH)
endif
ifneq (,$(INSTALLSHARE))
	    $(Q)$(INSTALLSUDO) $(MKDIR) $(DESTDIR)$(PREFIX)$(PATHSEP)$(INSTALLSHARERELPATH)
	    $(Q)$(INSTALLSUDO) $(CP) $(INSTALLSHARE) $(DESTDIR)$(PREFIX)$(PATHSEP)$(INSTALLSHARERELPATH)
	    $(Q)$(INSTALLSUDO) $(CP) src/pm3.py $(DESTDIR)$(PREFIX)$(PATHSEP)$(INSTALLSHARERELPATH)/pyscripts
endif
	@true

uninstall:
	$(info [@] Uninstalling client from $(DESTDIR)$(PREFIX)...)
ifneq (,$(INSTALLBIN))
	    $(Q)$(INSTALLSUDO) $(RM) $(foreach tool,$(INSTALLBIN),$(DESTDIR)$(PREFIX)$(PATHSEP)$(INSTALLBINRELPATH)$(PATHSEP)$(notdir $(tool)))
endif
ifneq (,$(INSTALLSHARE))
	    $(Q)$(INSTALLSUDO) $(RMDIR) $(foreach tool,$(INSTALLSHARE),$(DESTDIR)$(PREFIX)$(PATHSEP)$(INSTALLSHARERELPATH)$(PATHSEP)$(notdir $(tool)))
endif
	@true

tarbin: $(BINS)
	$(info [=] TAR ../proxmark3-$(platform)-bin.tar)
	$(Q)$(TAR) $(TARFLAGS) ../proxmark3-$(platform)-bin.tar $(BINS:%=client/%) $(WINBINS:%=client/%)

###########################
# local libraries targets #
###########################
$(AMIIBOLIB): .FORCE
	$(info [*] MAKE $@)
	$(Q)$(MAKE) --no-print-directory -C $(AMIIBOLIBPATH) all

$(CLIPARSERLIB): .FORCE
	$(info [*] MAKE $@)
	$(Q)$(MAKE) --no-print-directory -C $(CLIPARSERLIBPATH) all

$(HARDNESTEDLIB): .FORCE
	$(info [*] MAKE $@)
	$(Q)$(MAKE) --no-print-directory -C $(HARDNESTEDLIBPATH) all

$(JANSSONLIB): .FORCE
ifneq ($(JANSSON_FOUND),1)
	$(info [*] MAKE $@)
	$(Q)$(MAKE) --no-print-directory -C $(JANSSONLIBPATH) all
endif

$(LINENOISELIB): .FORCE
ifeq ($(LINENOISE_LOCAL_FOUND), 1)
	$(info [*] MAKE $@)
	$(Q)$(MAKE) --no-print-directory -C $(LINENOISELIBPATH) all
endif

$(LUALIB): .FORCE
ifneq ($(LUA_FOUND),1)
	$(info [*] MAKE $@ for $(LUAPLATFORM))
	$(Q)$(MAKE) --no-print-directory -C $(LUALIBPATH) $(LUAPLATFORM)
endif

$(MBEDTLSLIB): .FORCE
	$(info [*] MAKE $@)
	$(Q)$(MAKE) --no-print-directory -C $(MBEDTLSLIBPATH) OBJDIR=$(MBEDTLSLIBCLIENTRELPATH)/$(OBJDIR)/mbedtls BINDIR=$(MBEDTLSLIBCLIENTRELPATH)/$(OBJDIR) all

$(REVENGLIB): .FORCE
	$(info [*] MAKE $@)
	$(Q)$(MAKE) --no-print-directory -C $(REVENGLIBPATH) all

$(TINYCBORLIB): .FORCE
	$(info [*] MAKE $@)
	$(Q)$(MAKE) --no-print-directory -C $(TINYCBORLIBPATH) all

$(WHEREAMILIB): .FORCE
ifneq ($(WHEREAMI_FOUND),1)
	$(info [*] MAKE $@)
	$(Q)$(MAKE) --no-print-directory -C $(WHEREAMILIBPATH) all
endif

########
# SWIG #
########

src/pm3_luawrap.c: pm3.i
	$(info [=] GEN $@)
	$(Q)$(SWIG) -lua -o $@ $<

src/pm3_pywrap.c: pm3.i
	$(info [=] GEN $@)
	$(Q)$(SWIG) -python -o $@ $<

########
# misc #
########

.PHONY: all clean install uninstall tarbin .FORCE

# version_pm3.c should be checked on every compilation
src/version_pm3.c: default_version_pm3.c .FORCE
	$(info [=] CHECK $@)
	$(Q)$(SH) ../tools/mkversion.sh $@ || $(CP) $< $@

# easy printing of MAKE VARIABLES
print-%: ; @echo $* = $($*)

# SWIG files emit a number of warnings, we've to ignore them
%wrap.o: %wrap.c
$(OBJDIR)/%wrap.o : %wrap.c $(OBJDIR)/%.d
	$(info [-] CC $<)
	$(Q)$(MKDIR) $(dir $@)
	$(Q)$(CC) $(DEPFLAGS) $(PM3CFLAGS) -Wno-missing-prototypes -Wno-missing-declarations -Wno-missing-field-initializers -c -o $@ $<
	$(Q)$(POSTCOMPILE)

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
                   $(patsubst %wrap.c, $(OBJDIR)/%.d, $(SWIGSRCS)) \
                   $(patsubst %.cpp, $(OBJDIR)/%.d, $(CXXSRCS)) \
                   $(patsubst %.m, $(OBJDIR)/%.d, $(OBJCSRCS))

$(DEPENDENCY_FILES): ;
.PRECIOUS: $(DEPENDENCY_FILES)

-include $(DEPENDENCY_FILES)
