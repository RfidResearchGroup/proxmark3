add_library(z STATIC
        ../../common/zlib/deflate.c
        ../../common/zlib/adler32.c
        ../../common/zlib/trees.c
        ../../common/zlib/zutil.c
        ../../common/zlib/inflate.c
        ../../common/zlib/inffast.c
        ../../common/zlib/inftrees.c
)

target_compile_definitions(z PRIVATE Z_SOLO NO_GZIP ZLIB_PM3_TUNED)
target_compile_options(z PRIVATE -Wall -Werror -O3)
