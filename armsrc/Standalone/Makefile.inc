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
# Generic standalone Mode injection of source code
#-----------------------------------------------------------------------------

SRC_STANDALONE = placeholder.c
# WITH_STANDALONE_LF_SKELETON
ifneq (,$(findstring WITH_STANDALONE_LF_SKELETON,$(APP_CFLAGS)))
    SRC_STANDALONE = lf_skeleton.c
endif
# WITH_STANDALONE_LF_EM4100EMUL
ifneq (,$(findstring WITH_STANDALONE_LF_EM4100EMUL,$(APP_CFLAGS)))
    SRC_STANDALONE = lf_em4100emul.c
endif
# WITH_STANDALONE_LF_EM4100RSWB
ifneq (,$(findstring WITH_STANDALONE_LF_EM4100RSWB,$(APP_CFLAGS)))
    SRC_STANDALONE = lf_em4100rswb.c
endif
# WITH_STANDALONE_LF_EM4100RSWW
ifneq (,$(findstring WITH_STANDALONE_LF_EM4100RSWW,$(APP_CFLAGS)))
    SRC_STANDALONE = lf_em4100rsww.c
endif
# WITH_STANDALONE_LF_EM4100RWC
ifneq (,$(findstring WITH_STANDALONE_LF_EM4100RWC,$(APP_CFLAGS)))
    SRC_STANDALONE = lf_em4100rwc.c
endif
# WITH_STANDALONE_LF_HIDBRUTE
ifneq (,$(findstring WITH_STANDALONE_LF_HIDBRUTE,$(APP_CFLAGS)))
    SRC_STANDALONE = lf_hidbrute.c
endif
# WITH_STANDALONE_LF_HIDFCBRUTE
ifneq (,$(findstring WITH_STANDALONE_LF_HIDFCBRUTE,$(APP_CFLAGS)))
    SRC_STANDALONE = lf_hidfcbrute.c
endif
# WITH_STANDALONE_LF_ICEHID
ifneq (,$(findstring WITH_STANDALONE_LF_ICEHID,$(APP_CFLAGS)))
    SRC_STANDALONE = lf_icehid.c
endif
# WITH_STANDALONE_LF_MULTIHID
ifneq (,$(findstring WITH_STANDALONE_LF_MULTIHID,$(APP_CFLAGS)))
    SRC_STANDALONE = lf_multihid.c
endif
# WITH_STANDALONE_LF_NEDAP_SIM
ifneq (,$(findstring WITH_STANDALONE_LF_NEDAP_SIM,$(APP_CFLAGS)))
    SRC_STANDALONE = lf_nedap_sim.c
endif
# WITH_STANDALONE_LF_NEXID
ifneq (,$(findstring WITH_STANDALONE_LF_NEXID,$(APP_CFLAGS)))
    SRC_STANDALONE = lf_nexid.c
endif
# WITH_STANDALONE_LF_SAMYRUN
ifneq (,$(findstring WITH_STANDALONE_LF_SAMYRUN,$(APP_CFLAGS)))
    SRC_STANDALONE = lf_samyrun.c
endif
# WITH_STANDALONE_LF_PROXBRUTE
ifneq (,$(findstring WITH_STANDALONE_LF_PROXBRUTE,$(APP_CFLAGS)))
    SRC_STANDALONE = lf_proxbrute.c
endif
# WITH_STANDALONE_LF_PROX2BRUTE
ifneq (,$(findstring WITH_STANDALONE_LF_PROX2BRUTE,$(APP_CFLAGS)))
    SRC_STANDALONE = lf_prox2brute.c
endif
# WITH_STANDALONE_LF_THAREXDE
ifneq (,$(findstring WITH_STANDALONE_LF_THAREXDE,$(APP_CFLAGS)))
    SRC_STANDALONE = lf_tharexde.c
endif
# WITH_STANDALONE_HF_14ASNIFF
ifneq (,$(findstring WITH_STANDALONE_HF_14ASNIFF,$(APP_CFLAGS)))
    SRC_STANDALONE = hf_14asniff.c
endif
# WITH_STANDALONE_HF_14BSNIFF
ifneq (,$(findstring WITH_STANDALONE_HF_14BSNIFF,$(APP_CFLAGS)))
    SRC_STANDALONE = hf_14bsniff.c
endif
# WITH_STANDALONE_HF_15SNIFF
ifneq (,$(findstring WITH_STANDALONE_HF_15SNIFF,$(APP_CFLAGS)))
    SRC_STANDALONE = hf_15sniff.c
endif
# WITH_STANDALONE_HF_AVEFUL
ifneq (,$(findstring WITH_STANDALONE_HF_AVEFUL,$(APP_CFLAGS)))
    SRC_STANDALONE = hf_aveful.c
endif
# WITH_STANDALONE_HF_BOG
ifneq (,$(findstring WITH_STANDALONE_HF_BOG,$(APP_CFLAGS)))
    SRC_STANDALONE = hf_bog.c
endif
# WITH_STANDALONE_HF_CARDHOPPER
ifneq (,$(findstring WITH_STANDALONE_HF_CARDHOPPER,$(APP_CFLAGS)))
    SRC_STANDALONE = hf_cardhopper.c
endif
# WITH_STANDALONE_HF_COLIN
ifneq (,$(findstring WITH_STANDALONE_HF_COLIN,$(APP_CFLAGS)))
    SRC_STANDALONE = vtsend.c hf_colin.c frozen.c nprintf.c
endif
# WITH_STANDALONE_HF_CRAFTBYTE
ifneq (,$(findstring WITH_STANDALONE_HF_CRAFTBYTE,$(APP_CFLAGS)))
    SRC_STANDALONE = hf_craftbyte.c
endif
# WITH_STANDALONE_HF_ICECLASS
ifneq (,$(findstring WITH_STANDALONE_HF_ICECLASS,$(APP_CFLAGS)))
    SRC_STANDALONE = hf_iceclass.c
endif
# WITH_STANDALONE_HF_LEGIC
ifneq (,$(findstring WITH_STANDALONE_HF_LEGIC,$(APP_CFLAGS)))
   SRC_STANDALONE = hf_legic.c
endif
# WITH_STANDALONE_HF_LEGICSIM
ifneq (,$(findstring WITH_STANDALONE_HF_LEGICSIM,$(APP_CFLAGS)))
   SRC_STANDALONE = hf_legicsim.c
endif
# WITH_STANDALONE_HF_MATTYRUN
ifneq (,$(findstring WITH_STANDALONE_HF_MATTYRUN,$(APP_CFLAGS)))
    SRC_STANDALONE = hf_mattyrun.c
endif
# WITH_STANDALONE_HF_MFCSIM
ifneq (,$(findstring WITH_STANDALONE_HF_MFCSIM,$(APP_CFLAGS)))
    SRC_STANDALONE = hf_mfcsim.c
endif
# WITH_STANDALONE_HF_MSDSAL
ifneq (,$(findstring WITH_STANDALONE_HF_MSDSAL,$(APP_CFLAGS)))
    SRC_STANDALONE = hf_msdsal.c
endif
# WITH_STANDALONE_HF_REBLAY
ifneq (,$(findstring WITH_STANDALONE_HF_REBLAY,$(APP_CFLAGS)))
    SRC_STANDALONE = hf_reblay.c
endif
# WITH_STANDALONE_HF_TCPRST
ifneq (,$(findstring WITH_STANDALONE_HF_TCPRST,$(APP_CFLAGS)))
    SRC_STANDALONE = hf_tcprst.c
endif
# WITH_STANDALONE_HF_TMUDFORD
ifneq (,$(findstring WITH_STANDALONE_HF_TMUDFORD,$(APP_CFLAGS)))
    SRC_STANDALONE = hf_tmudford.c
endif
# WITH_STANDALONE_HF_YOUNG
ifneq (,$(findstring WITH_STANDALONE_HF_YOUNG,$(APP_CFLAGS)))
    SRC_STANDALONE = hf_young.c
endif

ifneq (,$(findstring WITH_STANDALONE_DANKARMULTI,$(APP_CFLAGS)))
    SRC_STANDALONE = dankarmulti.c
endif
