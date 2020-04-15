set_property(SOURCE PROPERTY C_STANDARD 99)
add_definitions(-DPRESETS)
include_directories(reveng)
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

