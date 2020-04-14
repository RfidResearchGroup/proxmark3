# just for testing amiitool before complete migration into a lib:

#amiitool:
#gcc $(CFLAGS) \
#amiitool.c $(MYSRCS) ../../common/commonutil.c ../ui.c -lreadline -lm ../../common/mbedtls/libmbedtls.a \
#-o amiitool

set_property(SOURCE PROPERTY C_STANDARD 99)
add_definitions(-D_ISOC99_SOURCE)
include_directories(jansson)
include_directories(common)
include_directories(common/include)
include_directories(amiitool)

add_library(amiibo
        jansson/dump.c
        jansson/error.c
        jansson/hashtable.c
        jansson/hashtable_seed.c
        jansson/load.c
        jansson/memory.c
        jansson/pack_unpack.c
        jansson/strbuffer.c
        jansson/strconv.c
        jansson/utf.c
        jansson/path.c
        jansson/value.c
)
