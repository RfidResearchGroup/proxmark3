add_library(cliparser STATIC
        cliparser/argtable3.c
        cliparser/cliparser.c
)

target_include_directories(cliparser PRIVATE
        ../../common
        ../../include
        ../src)
target_include_directories(cliparser INTERFACE cliparser)
target_compile_options(cliparser PRIVATE -Wall -Werror -O3)
