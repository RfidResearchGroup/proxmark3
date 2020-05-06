add_library(pm3rrg_rdv4_z STATIC
        ../../common/zlib/deflate.c
        ../../common/zlib/adler32.c
        ../../common/zlib/trees.c
        ../../common/zlib/zutil.c
        ../../common/zlib/inflate.c
        ../../common/zlib/inffast.c
        ../../common/zlib/inftrees.c
)

target_compile_definitions(pm3rrg_rdv4_z PRIVATE Z_SOLO NO_GZIP ZLIB_PM3_TUNED)
target_compile_options(pm3rrg_rdv4_z PRIVATE -Wall -Werror -O3)
set_property(TARGET pm3rrg_rdv4_z PROPERTY POSITION_INDEPENDENT_CODE ON)
