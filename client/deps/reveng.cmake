set_property(SOURCE PROPERTY C_STANDARD 99)
include_directories(.)

add_library(reveng
        reveng/bmpbit.c
        reveng/cli.c
        reveng/getopt.c
        reveng/model.c
        reveng/poly.c
        reveng/preset.c
        reveng/reveng.c
)

target_compile_definitions(reveng PRIVATE PRESETS)
