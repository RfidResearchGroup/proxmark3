add_library(pm3rrg_rdv4_jansson STATIC
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
        jansson/value.c
)

target_compile_definitions(pm3rrg_rdv4_jansson PRIVATE HAVE_STDINT_H)
target_include_directories(pm3rrg_rdv4_jansson INTERFACE jansson)
target_compile_options(pm3rrg_rdv4_jansson PRIVATE -Wall -Wno-unused-function -O3)
set_property(TARGET pm3rrg_rdv4_jansson PROPERTY POSITION_INDEPENDENT_CODE ON)
