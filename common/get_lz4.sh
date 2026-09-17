#-----------------------------------------------------------------------------
# Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# See LICENSE.txt for the text of the license.
#-----------------------------------------------------------------------------

version=1.9.2
mkdir -p lz4
wget https://github.com/lz4/lz4/archive/v$version.zip
unzip -o -j v$version "lz4-$version/LICENSE" "lz4-$version/lib/lz4.h" "lz4-$version/lib/lz4.c" "lz4-$version/lib/lz4hc.h" "lz4-$version/lib/lz4hc.c" -d lz4
rm v$version.zip
patch -p0 << EOF
diff -Naur lz4/lz4.c lz4/lz4.c
--- lz4/lz4.c
+++ lz4/lz4.c
@@ -1270,6 +1270,7 @@ int LZ4_compress_default(const char* src, char* dst, int srcSize, int maxOutputS
 }
 
 
+int LZ4_compress_fast_force(const char* src, char* dst, int srcSize, int dstCapacity, int acceleration);
 /* hidden debug function */
 /* strangely enough, gcc generates faster code when this function is uncommented, even if unused */
 int LZ4_compress_fast_force(const char* src, char* dst, int srcSize, int dstCapacity, int acceleration)
@@ -1644,13 +1645,16 @@ read_variable_length(const BYTE**ip, const BYTE* lencheck, int loop_check, int i
   return length;
 }
 
+int LZ4_decompress_generic(const char* const src, char* const dst, int srcSize, int outputSize, endCondition_directive endOnInput, earlyEnd_directive partialDecoding,
+                 dict_directive dict, const BYTE* const lowPrefix, const BYTE* const dictStart, const size_t dictSize );
+
 /*! LZ4_decompress_generic() :
  *  This generic decompression function covers all use cases.
  *  It shall be instantiated several times, using different sets of directives.
  *  Note that it is important for performance that this function really get inlined,
  *  in order to remove useless branches during compilation optimization.
  */
-LZ4_FORCE_INLINE int
+int
 LZ4_decompress_generic(
                  const char* const src,
                  char* const dst,
EOF
