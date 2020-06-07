version=1.9.2
mkdir -p lz4
wget https://github.com/lz4/lz4/archive/v$version.zip
unzip -o -j v$version "lz4-$version/LICENSE" "lz4-$version/lib/lz4.h" "lz4-$version/lib/lz4.c" "lz4-$version/lib/lz4hc.h" "lz4-$version/lib/lz4hc.c" -d lz4
rm v$version.zip
patch -p0 << EOF
diff -Naur lz4/lz4.c lz4/lz4.c
--- lz4/lz4.c	2019-08-15 13:59:59.000000000 +0200
+++ lz4/lz4.c	2020-06-07 12:50:11.788924953 +0200
@@ -1650,7 +1650,7 @@
  *  Note that it is important for performance that this function really get inlined,
  *  in order to remove useless branches during compilation optimization.
  */
-LZ4_FORCE_INLINE int
+int
 LZ4_decompress_generic(
                  const char* const src,
                  char* const dst,
EOF
