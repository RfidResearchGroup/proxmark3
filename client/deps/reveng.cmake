add_library(reveng STATIC
        reveng/bmpbit.c
        reveng/cli.c
        reveng/model.c
        reveng/poly.c
        reveng/preset.c
        reveng/reveng.c
)

target_compile_definitions(reveng PRIVATE PRESETS)
target_include_directories(reveng PRIVATE ../cliparser)
target_include_directories(reveng INTERFACE reveng)
target_compile_options(reveng PRIVATE -Wall -Werror -O3)
set_property(TARGET reveng PROPERTY POSITION_INDEPENDENT_CODE ON)
