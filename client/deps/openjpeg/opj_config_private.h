#ifndef OPJ_CONFIG_PRIVATE_H_INCLUDED
#define OPJ_CONFIG_PRIVATE_H_INCLUDED

/*
 * Hand written replacement for the CMake generated opj_config_private.h
 *
 * Upstream probes the host with CMake try_compile checks.  We vendor the
 * sources instead, so everything is decided from compiler predefines here.
 * This file is included before any system header, see opj_includes.h
 */

#define OPJ_PACKAGE_VERSION "2.5.4"

/*
 * Aligned allocation.
 *
 * On POSIX we take posix_memalign, it is declared by <stdlib.h> and openjpeg
 * prefers it over memalign anyway.
 *
 * On Windows / MinGW we deliberately define nothing.  openjpeg then falls back
 * to its own portable aligned malloc, which avoids having to reason about
 * whether _aligned_malloc is visible in a given mingw-w64 / msvcrt combination.
 * We decode a handful of passport images, the alloc path is not hot.
 */
#if !defined(_WIN32)
#  define OPJ_HAVE_POSIX_MEMALIGN
#  define OPJ_HAVE_FSEEKO
#endif

#if !defined(_POSIX_C_SOURCE)
#  if defined(OPJ_HAVE_FSEEKO) || defined(OPJ_HAVE_POSIX_MEMALIGN)
/* Get declarations of fseeko, ftello, posix_memalign. */
#    define _POSIX_C_SOURCE 200112L
#  endif
#endif

/* Byte order, taken from the compiler rather than from a TRY_RUN */
#if defined(__BIG_ENDIAN__)
#  define OPJ_BIG_ENDIAN
#elif defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__) && (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
#  define OPJ_BIG_ENDIAN
#endif

#endif
