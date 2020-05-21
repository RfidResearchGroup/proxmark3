# just for testing amiitool before complete migration into a lib:

#amiitool:
#gcc $(CFLAGS) \
#amiitool.c $(MYSRCS) ../../../../common/../../commonutil.c ../ui.c -lreadline -lm ../../../../common/mbedtls/libmbedtls.a \
#-o amiitool

add_library(pm3rrg_rdv4_amiibo STATIC
        amiitool/amiibo.c
        amiitool/drbg.c
        amiitool/keygen.c
)

target_include_directories(pm3rrg_rdv4_amiibo PRIVATE ../../include ../../common)
target_include_directories(pm3rrg_rdv4_amiibo INTERFACE amiitool)
target_compile_options(pm3rrg_rdv4_amiibo PRIVATE -Wall -O3)
set_property(TARGET pm3rrg_rdv4_amiibo PROPERTY POSITION_INDEPENDENT_CODE ON)
