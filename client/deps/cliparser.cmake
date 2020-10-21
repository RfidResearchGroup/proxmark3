add_library(pm3rrg_rdv4_cliparser STATIC
        cliparser/argtable3.c
        cliparser/cliparser.c
)

target_compile_definitions(pm3rrg_rdv4_cliparser PRIVATE _ISOC99_SOURCE)
target_include_directories(pm3rrg_rdv4_cliparser PRIVATE
        ../../common
        ../../include
        ../src)
target_include_directories(pm3rrg_rdv4_cliparser INTERFACE cliparser)
target_compile_options(pm3rrg_rdv4_cliparser PRIVATE -Wall -Werror -O3)
set_property(TARGET pm3rrg_rdv4_cliparser PROPERTY POSITION_INDEPENDENT_CODE ON)
