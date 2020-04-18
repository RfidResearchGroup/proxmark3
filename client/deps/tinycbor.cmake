add_library(tinycbor STATIC
        tinycbor/cborencoder.c
        tinycbor/cborencoder_close_container_checked.c
        tinycbor/cborerrorstrings.c
        tinycbor/cborparser.c
        tinycbor/cborparser_dup_string.c
        tinycbor/cborpretty.c
        tinycbor/cbortojson.c
        tinycbor/cborvalidation.c
        )

target_include_directories(tinycbor INTERFACE tinycbor)
# Strange errors on Mingw when compiling with -O3
target_compile_options(tinycbor PRIVATE -Wall -Werror -O2)
