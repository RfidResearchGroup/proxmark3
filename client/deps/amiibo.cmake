# just for testing amiitool before complete migration into a lib:

#amiitool:
#gcc $(CFLAGS) \
#amiitool.c $(MYSRCS) ../../../../common/../../commonutil.c ../ui.c -lreadline -lm ../../../../common/mbedtls/libmbedtls.a \
#-o amiitool

add_library(amiibo STATIC
        amiitool/amiibo.c
        amiitool/drbg.c
        amiitool/keygen.c
)

target_include_directories(amiibo PRIVATE ../../include ../../common)
target_include_directories(amiibo INTERFACE amiitool)
target_compile_options(amiibo PRIVATE -Wall -Werror -O3)
