# just for testing amiitool before complete migration into a lib:

#amiitool:
#gcc $(CFLAGS) \
#amiitool.c $(MYSRCS) ../../../../common/../../commonutil.c ../ui.c -lreadline -lm ../../../../common/mbedtls/libmbedtls.a \
#-o amiitool

set_property(SOURCE PROPERTY C_STANDARD 99)

add_library(amiibo
        amiitool/amiibo.c
        amiitool/drbg.c
        amiitool/keygen.c
)

target_include_directories(amiibo PRIVATE ../../include ../../common)
