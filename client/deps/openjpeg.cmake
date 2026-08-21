# Vendored openjpeg (openjp2), decoder + encoder core, BSD-2-Clause.
# Only the sources listed in upstream OPENJPEG_SRCS are kept, JPIP index
# handling is left out.  See client/deps/openjpeg/README.pm3
add_library(pm3rrg_rdv4_openjpeg STATIC
        openjpeg/bio.c
        openjpeg/cio.c
        openjpeg/dwt.c
        openjpeg/event.c
        openjpeg/function_list.c
        openjpeg/ht_dec.c
        openjpeg/image.c
        openjpeg/invert.c
        openjpeg/j2k.c
        openjpeg/jp2.c
        openjpeg/mct.c
        openjpeg/mqc.c
        openjpeg/openjpeg.c
        openjpeg/opj_clock.c
        openjpeg/opj_malloc.c
        openjpeg/pi.c
        openjpeg/sparse_array.c
        openjpeg/t1.c
        openjpeg/t2.c
        openjpeg/tcd.c
        openjpeg/tgt.c
        openjpeg/thread.c
        )

target_include_directories(pm3rrg_rdv4_openjpeg INTERFACE openjpeg)
target_include_directories(pm3rrg_rdv4_openjpeg PRIVATE openjpeg)
# openjpeg.a is a static lib, avoid __declspec(dllimport) on its Windows API decls
target_compile_definitions(pm3rrg_rdv4_openjpeg PUBLIC OPJ_STATIC)
# Third party code, don't hold it to our warning settings
target_compile_options(pm3rrg_rdv4_openjpeg PRIVATE -w -O3)
set_property(TARGET pm3rrg_rdv4_openjpeg PROPERTY POSITION_INDEPENDENT_CODE ON)
find_package(Threads REQUIRED)
target_link_libraries(pm3rrg_rdv4_openjpeg PRIVATE Threads::Threads)
