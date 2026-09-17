add_library(pm3rrg_rdv4_reveng STATIC
        reveng/bmpbit.c
        reveng/cli.c
        reveng/model.c
        reveng/poly.c
        reveng/preset.c
        reveng/reveng.c
)

target_compile_definitions(pm3rrg_rdv4_reveng PRIVATE PRESETS)
target_include_directories(pm3rrg_rdv4_reveng PRIVATE
        cliparser
        ../src
        ../../include)
target_include_directories(pm3rrg_rdv4_reveng INTERFACE reveng)
target_compile_options(pm3rrg_rdv4_reveng PRIVATE -Wall -O3)
set_property(TARGET pm3rrg_rdv4_reveng PROPERTY POSITION_INDEPENDENT_CODE ON)
