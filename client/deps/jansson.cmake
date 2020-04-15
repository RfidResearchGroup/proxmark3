set_property(SOURCE PROPERTY C_STANDARD 99)
add_definitions(-DHAVE_STDINT_H)
include_directories(jansson)

add_library(jansson
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
