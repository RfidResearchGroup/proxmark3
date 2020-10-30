add_library(pm3rrg_rdv4_tinycbor STATIC
        tinycbor/cborencoder.c
        tinycbor/cborencoder_close_container_checked.c
        tinycbor/cborerrorstrings.c
        tinycbor/cborparser.c
        tinycbor/cborparser_dup_string.c
        tinycbor/cborpretty.c
        tinycbor/cbortojson.c
        tinycbor/cborvalidation.c
        )

target_include_directories(pm3rrg_rdv4_tinycbor INTERFACE tinycbor)
# Strange errors on Mingw when compiling with -O3
target_compile_options(pm3rrg_rdv4_tinycbor PRIVATE -Wall -Werror -O2)
set_property(TARGET pm3rrg_rdv4_tinycbor PROPERTY POSITION_INDEPENDENT_CODE ON)
