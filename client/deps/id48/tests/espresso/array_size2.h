/**

The MIT License (MIT)

Copyright (c) SimpleHacks, Henry Gabryjelski
https://github.com/SimpleHacks/UtilHeaders

All rights reserved.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

*/

#ifndef ARRAYSIZE2_H
#define ARRAYSIZE2_H

/**
    The following, if defined prior to inclusion of this header file,
    will modify its behavior as noted:

        ARRAYSIZE2_SHOW_VERSION_MESSAGE
        -- if defined, will show which version of ARRAY_SIZE2 macro is selected
 */


/**
    see example source at:
    https://godbolt.org/z/zzYoeK6Mf
*/

#ifndef __has_feature
    #define __has_feature(x) 0 /* Compatibility with non-clang compilers. */
#endif

#if (defined(__cplusplus) && __cplusplus >= 201103L) ||    /* any compiler claiming C++11 support */ \
    (defined(__cplusplus) && _MSC_VER >= 1900 && __cplusplus != 199711L) ||    /* Visual C++ 2015 or higher           */ \
    __has_feature(cxx_constexpr) /* CLang versions supporting constexp  */

    #include <stddef.h> /* required for size_t */
    #if defined(ARRAYSIZE2_SHOW_VERSION_MESSAGE)
        #pragma message( "ARRAY_SIZE2 -- Using C++11 version" )
    #endif

    namespace detail
    {
        template <typename T, size_t N>
        constexpr size_t ARRAY_SIZE2_ARGUMENT_CANNOT_BE_POINTER(T const (&)[N]) noexcept
        {
            return N;
        }
    } /* namespace detail */
    #define ARRAY_SIZE2(arr) detail::ARRAY_SIZE2_ARGUMENT_CANNOT_BE_POINTER(arr)

#elif defined(__cplusplus) && __cplusplus >= 199711L && ( /* C++ 98 trick */   \
      defined(__INTEL_COMPILER) ||                     \
      defined(__clang__) ||                            \
      (defined(__GNUC__) && (                          \
          (__GNUC__ > 4) ||                            \
          (__GNUC__ == 4 && __GNUC_MINOR__ >= 4)       \
      )))

    #include <stddef.h> /* required for size_t */
    #if defined(ARRAYSIZE2_SHOW_VERSION_MESSAGE)
        #pragma message "ARRAY_SIZE2 -- Using C++98 version"
    #endif
    template <typename T, size_t N>
    char(&_ArraySizeHelperRequiresArray(T(&)[N]))[N];
    #define ARRAY_SIZE2(x) sizeof(_ArraySizeHelperRequiresArray(x))

#elif defined(__cplusplus) /* && ((__cplusplus >= 199711L) || defined(__INTEL_COMPILER) || defined(__clang__)) */
    
    #if defined(ARRAYSIZE2_SHOW_VERSION_MESSAGE)
        #pragma message( "ARRAY_SIZE2 -- Using Ivan J. Johnson's C++ version" )
    #endif
    /*
        Works on older compilers, even Visual C++ 6....
        Created by Ivan J. Johnson, March 06, 2007
        See http://drdobbs.com/cpp/197800525?pgno=1

        Full description is in markdown file array_size2.md
    */
    #define ARRAY_SIZE2(arr) ( \
       0 * sizeof(reinterpret_cast<const ::Bad_arg_to_ARRAY_SIZE2*>(arr)) + /*check1*/ \
       0 * sizeof(::Bad_arg_to_ARRAY_SIZE2::check_type((arr), &(arr)))    + /*check2*/ \
       sizeof(arr) / sizeof((arr)[0])                                       /* eval */ \
       )

    struct Bad_arg_to_ARRAY_SIZE2 {
       class Is_pointer; /* incomplete */
       class Is_array {};
       template <typename T>
       static Is_pointer check_type(T const *, T const * const *);
       static Is_array check_type(void const *, void const *);
    };

#elif !defined(__cplusplus) && defined(__GNUC__)

    #include <stdint.h>

    /**
        Even C can have type-safety for equivalent of ARRAY_SIZE() macro,
        when using the following two GCC extensions:
           typeof()
           __builtin_types_compatible_p()
    */

    #if defined(ARRAYSIZE2_SHOW_VERSION_MESSAGE)
        #pragma message( "ARRAY_SIZE2 -- Using GNUC version" )
    #endif

    /**
        validated using:
          MSP430  gcc   4.5.3
          x86-64  icc  16.0.3
          x86-64  gcc   4.1.2
          x86-64 clang  3.0.0
          AVR     gcc   4.5.4
          ARM     gcc   4.5.4
    */

    #define __SIMPLEHACKS_COMPATIBLE_TYPES__(a,b)   __builtin_types_compatible_p(__typeof__(a), __typeof__(b)) /* GCC extensions */
    #define __SIMPLEHACKS_BUILD_ERROR_ON_NONZERO__(x)  (sizeof(struct { uint8_t q: (-!!(x)*0x1ee7)+1u;})-1u) /* if x is zero, reports "error: negative width in bit-field '<anonymous>'" */
    #define __SIMPLEHACKS_MUST_BE_ARRAY__(x)        __SIMPLEHACKS_BUILD_ERROR_ON_NONZERO__(__SIMPLEHACKS_COMPATIBLE_TYPES__((x), &(*x)))
    #define ARRAY_SIZE2(_arr)       ( (sizeof(_arr) / sizeof((_arr)[0])) + __SIMPLEHACKS_MUST_BE_ARRAY__(_arr) ) /* compile-time error if not an array */

#else

    /**
        The good news is that all compilers (as of 20202-05-08)
        on godbolt.org are fully supported.  Therefore, if some
        other compiler does not support any of the above method,
        it's important to force a compile-time error, to avoid
        any suggestion that this provides a safe macro.
    */
   
    #error "Unable to provide type-safe ARRAY_SIZE2 macro"


#endif

#endif  // ARRAYSIZE2_H
