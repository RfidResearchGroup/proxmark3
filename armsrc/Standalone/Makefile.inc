# Generic standalone Mode injection of source code

SRC_STANDALONE = placeholder.c
# WITH_STANDALONE_LF_ICERUN
ifneq (,$(findstring WITH_STANDALONE_LF_ICERUN,$(APP_CFLAGS)))
    SRC_STANDALONE = lf_icerun.c
endif
# WITH_STANDALONE_LF_SAMYRUN
ifneq (,$(findstring WITH_STANDALONE_LF_SAMYRUN,$(APP_CFLAGS)))
    SRC_STANDALONE = lf_samyrun.c
endif
# WITH_STANDALONE_LF_PROXBRUTE
ifneq (,$(findstring WITH_STANDALONE_LF_PROXBRUTE,$(APP_CFLAGS)))
    SRC_STANDALONE = lf_proxbrute.c
endif
# WITH_STANDALONE_LF_HIDBRUTE
ifneq (,$(findstring WITH_STANDALONE_LF_HIDBRUTE,$(APP_CFLAGS)))
    SRC_STANDALONE = lf_hidbrute.c
endif
# WITH_STANDALONE_HF_YOUNG
ifneq (,$(findstring WITH_STANDALONE_HF_YOUNG,$(APP_CFLAGS)))
    SRC_STANDALONE = hf_young.c
endif
# WITH_STANDALONE_HF_MATTYRUN
ifneq (,$(findstring WITH_STANDALONE_HF_MATTYRUN,$(APP_CFLAGS)))
    SRC_STANDALONE = hf_mattyrun.c
endif
# WITH_STANDALONE_HF_COLIN
ifneq (,$(findstring WITH_STANDALONE_HF_COLIN,$(APP_CFLAGS)))
    SRC_STANDALONE = vtsend.c hf_colin.c frozen.c nprintf.c
endif
# WITH_STANDALONE_HF_BOG
ifneq (,$(findstring WITH_STANDALONE_HF_BOG,$(APP_CFLAGS)))
    SRC_STANDALONE = hf_bog.c
endif
# WITH_STANDALONE_HF_14ASNIFF
ifneq (,$(findstring WITH_STANDALONE_HF_14ASNIFF,$(APP_CFLAGS)))
    SRC_STANDALONE = hf_14asniff.c
endif
# WITH_STANDALONE_LF_ICEHID
ifneq (,$(findstring WITH_STANDALONE_LF_ICEHID,$(APP_CFLAGS)))
    SRC_STANDALONE = lf_icehid.c
endif
# WITH_STANDALONE_LF_EM4100EMUL
ifneq (,$(findstring WITH_STANDALONE_LF_EM4100EMUL,$(APP_CFLAGS)))
    SRC_STANDALONE = lf_em4100emul.c
endif
# WITH_STANDALONE_LF_EM4100RWC
ifneq (,$(findstring WITH_STANDALONE_LF_EM4100RWC,$(APP_CFLAGS)))
    SRC_STANDALONE = lf_em4100rwc.c
endif
# WITH_STANDALONE_HF_LEGIC
ifneq (,$(findstring WITH_STANDALONE_HF_LEGIC,$(APP_CFLAGS)))
   SRC_STANDALONE = hf_legic.c
endif
# WITH_STANDALONE_LF_MSDSAL
ifneq (,$(findstring WITH_STANDALONE_HF_MSDSAL,$(APP_CFLAGS)))
    SRC_STANDALONE = hf_msdsal.c
endif
