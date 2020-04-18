set_property(SOURCE PROPERTY C_STANDARD 99)

add_library(jansson STATIC
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

target_compile_definitions(jansson PRIVATE HAVE_STDINT_H)
