set_property(SOURCE PROPERTY C_STANDARD 99)

add_library(hardnested_nosimd OBJECT
        hardnested/hardnested_bf_core.c
        hardnested/hardnested_bitarray_core.c)

target_compile_options(hardnested_nosimd PRIVATE -Wall -Werror -O3)

target_include_directories(hardnested_nosimd PRIVATE
        ../../common
        ../../include)

## CPU-specific code
## These are mostly for x86-based architectures, which is not useful for many Android devices.
## Mingw platforms: AMD64
set(X86_CPUS x86 x86_64 i686 AMD64)

message(STATUS "CMAKE_SYSTEM_PROCESSOR := ${CMAKE_SYSTEM_PROCESSOR}")

if ("${CMAKE_SYSTEM_PROCESSOR}" IN_LIST X86_CPUS)
    message(STATUS "Building optimised x86/x86_64 binaries")

    target_compile_options(hardnested_nosimd BEFORE PRIVATE
            -mno-mmx -mno-sse2 -mno-avx -mno-avx2 -mno-avx512f)

    ## x86 / MMX
    add_library(hardnested_mmx OBJECT
            hardnested/hardnested_bf_core.c
            hardnested/hardnested_bitarray_core.c)

    target_compile_options(hardnested_mmx PRIVATE -Wall -Werror -O3)
    target_compile_options(hardnested_mmx BEFORE PRIVATE
            -mmmx -mno-sse2 -mno-avx -mno-avx2 -mno-avx512f)

    target_include_directories(hardnested_mmx PRIVATE
            ../../common
            ../../include)

    ## x86 / SSE2
    add_library(hardnested_sse2 OBJECT
            hardnested/hardnested_bf_core.c
            hardnested/hardnested_bitarray_core.c)

    target_compile_options(hardnested_sse2 PRIVATE -Wall -Werror -O3)
    target_compile_options(hardnested_sse2 BEFORE PRIVATE
            -mmmx -msse2 -mno-avx -mno-avx2 -mno-avx512f)

    target_include_directories(hardnested_sse2 PRIVATE
            ../../common
            ../../include)

    ## x86 / AVX
    add_library(hardnested_avx OBJECT
            hardnested/hardnested_bf_core.c
            hardnested/hardnested_bitarray_core.c)

    target_compile_options(hardnested_avx PRIVATE -Wall -Werror -O3)
    target_compile_options(hardnested_avx BEFORE PRIVATE
            -mmmx -msse2 -mavx -mno-avx2 -mno-avx512f)

    target_include_directories(hardnested_avx PRIVATE
            ../../common
            ../../include)

    ## x86 / AVX2
    add_library(hardnested_avx2 OBJECT
            hardnested/hardnested_bf_core.c
            hardnested/hardnested_bitarray_core.c)

    target_compile_options(hardnested_avx2 PRIVATE -Wall -Werror -O3)
    target_compile_options(hardnested_avx2 BEFORE PRIVATE
            -mmmx -msse2 -mavx -mavx2 -mno-avx512f)

    target_include_directories(hardnested_avx2 PRIVATE
            ../../common
            ../../include)

    ## x86 / AVX512
    add_library(hardnested_avx512 OBJECT
            hardnested/hardnested_bf_core.c
            hardnested/hardnested_bitarray_core.c)

    target_compile_options(hardnested_avx512 PRIVATE -Wall -Werror -O3)
    target_compile_options(hardnested_avx512 BEFORE PRIVATE
            -mmmx -msse2 -mavx -mavx2 -mavx512f)

    target_include_directories(hardnested_avx512 PRIVATE
            ../../common
            ../../include)

    set(SIMD_TARGETS
            $<TARGET_OBJECTS:hardnested_mmx>
            $<TARGET_OBJECTS:hardnested_sse2>
            $<TARGET_OBJECTS:hardnested_avx>
            $<TARGET_OBJECTS:hardnested_avx2>
            $<TARGET_OBJECTS:hardnested_avx512>)
else ()
    message(STATUS "Not building optimised targets")
    set(SIMD_TARGETS)
endif ()

add_library(hardnested STATIC
        hardnested/hardnested_bruteforce.c
        $<TARGET_OBJECTS:hardnested_nosimd>
        ${SIMD_TARGETS})
target_include_directories(hardnested PRIVATE
        ../../common
        ../../include
        ../src
        jansson)
target_include_directories(hardnested INTERFACE hardnested)
