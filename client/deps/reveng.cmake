set_property(SOURCE PROPERTY C_STANDARD 99)

add_library(reveng STATIC
        reveng/bmpbit.c
        reveng/cli.c
        reveng/getopt.c
        reveng/model.c
        reveng/poly.c
        reveng/preset.c
        reveng/reveng.c
)

target_compile_definitions(reveng PRIVATE PRESETS)
target_include_directories(reveng PRIVATE .)
