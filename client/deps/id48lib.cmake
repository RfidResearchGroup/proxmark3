add_library(pm3rrg_rdv4_id48 STATIC
        id48/id48_data.c
        id48/id48_generator.c
        id48/id48_recover.c
)
target_compile_options(    pm3rrg_rdv4_id48 PRIVATE   -Wpedantic -Wall -O3 -Wno-unknown-pragmas -Wno-inline -Wno-unused-function -DID48_NO_STDIO)
target_include_directories(pm3rrg_rdv4_id48 PRIVATE   id48)
target_include_directories(pm3rrg_rdv4_id48 INTERFACE id48)
set_property(TARGET        pm3rrg_rdv4_id48 PROPERTY  POSITION_INDEPENDENT_CODE ON)
