# This is manually re-creating the contents of id48/src/CMakeLists.txt
# and thus must be manually kept in sync with updates to id48/src.
add_library(pm3rrg_rdv4_id48 STATIC
        id48/src/id48_data.c
        id48/src/id48_generator.c
        id48/src/id48_recover.c
)
target_compile_options(    pm3rrg_rdv4_id48 PRIVATE   -Wpedantic -Wall -Werror -O3 -Wno-unknown-pragmas -Wno-inline -Wno-unused-function -DID48_NO_STDIO)
target_include_directories(pm3rrg_rdv4_id48 PRIVATE   id48/public)
target_include_directories(pm3rrg_rdv4_id48 INTERFACE id48/public)
set_property(TARGET        pm3rrg_rdv4_id48 PROPERTY  POSITION_INDEPENDENT_CODE ON)
