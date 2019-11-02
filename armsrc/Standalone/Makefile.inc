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

