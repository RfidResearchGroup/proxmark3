add_library(pm3rrg_rdv4_linenoise STATIC
        linenoise-ng/ConvertUTF.cpp
        linenoise-ng/linenoise.cpp
        linenoise-ng/wcwidth.cpp
)

target_compile_definitions(pm3rrg_rdv4_linenoise PRIVATE NDEBUG)
target_include_directories(pm3rrg_rdv4_linenoise INTERFACE linenoise-ng)
target_compile_options(pm3rrg_rdv4_linenoise PRIVATE -Wall -Werror -O3 -std=c++11 -fomit-frame-pointer)
set_property(TARGET pm3rrg_rdv4_linenoise PROPERTY POSITION_INDEPENDENT_CODE ON)
