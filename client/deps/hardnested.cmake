add_library(pm3rrg_rdv4_hardnested_nosimd OBJECT
        hardnested/hardnested_bf_core.c
        hardnested/hardnested_bitarray_core.c)

target_compile_options(pm3rrg_rdv4_hardnested_nosimd PRIVATE -Wall -Werror -O3)
set_property(TARGET pm3rrg_rdv4_hardnested_nosimd PROPERTY POSITION_INDEPENDENT_CODE ON)

target_include_directories(pm3rrg_rdv4_hardnested_nosimd PRIVATE
        ../../common
        ../../include
        ../src)

target_compile_definitions(pm3rrg_rdv4_hardnested_nosimd PRIVATE NOSIMD_BUILD)

## CPU-specific code
## These are mostly for x86-based architectures, which is not useful for many Android devices.
## Mingw platforms: AMD64
set(X86_CPUS x86 x86_64 i686 AMD64)
set(ARM64_CPUS arm64 aarch64)
set(ARM32_CPUS armel armhf armv7-a)

message(STATUS "CMAKE_SYSTEM_PROCESSOR := ${CMAKE_SYSTEM_PROCESSOR}")

if ("${CMAKE_SYSTEM_PROCESSOR}" IN_LIST X86_CPUS)
    message(STATUS "Building optimised x86/x86_64 binaries")

    target_compile_options(pm3rrg_rdv4_hardnested_nosimd BEFORE PRIVATE
            -mno-mmx -mno-sse2 -mno-avx -mno-avx2 -mno-avx512f)

    ## x86 / MMX
    add_library(pm3rrg_rdv4_hardnested_mmx OBJECT
            hardnested/hardnested_bf_core.c
            hardnested/hardnested_bitarray_core.c)

    target_compile_options(pm3rrg_rdv4_hardnested_mmx PRIVATE -Wall -Werror -O3)
    target_compile_options(pm3rrg_rdv4_hardnested_mmx BEFORE PRIVATE
            -mmmx -mno-sse2 -mno-avx -mno-avx2 -mno-avx512f)
    set_property(TARGET pm3rrg_rdv4_hardnested_mmx PROPERTY POSITION_INDEPENDENT_CODE ON)

    target_include_directories(pm3rrg_rdv4_hardnested_mmx PRIVATE
            ../../common
            ../../include
            ../src)

    ## x86 / SSE2
    add_library(pm3rrg_rdv4_hardnested_sse2 OBJECT
            hardnested/hardnested_bf_core.c
            hardnested/hardnested_bitarray_core.c)

    target_compile_options(pm3rrg_rdv4_hardnested_sse2 PRIVATE -Wall -Werror -O3)
    target_compile_options(pm3rrg_rdv4_hardnested_sse2 BEFORE PRIVATE
            -mmmx -msse2 -mno-avx -mno-avx2 -mno-avx512f)
    set_property(TARGET pm3rrg_rdv4_hardnested_sse2 PROPERTY POSITION_INDEPENDENT_CODE ON)

    target_include_directories(pm3rrg_rdv4_hardnested_sse2 PRIVATE
            ../../common
            ../../include
            ../src)

    ## x86 / AVX
    add_library(pm3rrg_rdv4_hardnested_avx OBJECT
            hardnested/hardnested_bf_core.c
            hardnested/hardnested_bitarray_core.c)

    target_compile_options(pm3rrg_rdv4_hardnested_avx PRIVATE -Wall -Werror -O3)
    target_compile_options(pm3rrg_rdv4_hardnested_avx BEFORE PRIVATE
            -mmmx -msse2 -mavx -mno-avx2 -mno-avx512f)
    set_property(TARGET pm3rrg_rdv4_hardnested_avx PROPERTY POSITION_INDEPENDENT_CODE ON)

    target_include_directories(pm3rrg_rdv4_hardnested_avx PRIVATE
            ../../common
            ../../include
            ../src)

    ## x86 / AVX2
    add_library(pm3rrg_rdv4_hardnested_avx2 OBJECT
            hardnested/hardnested_bf_core.c
            hardnested/hardnested_bitarray_core.c)

    target_compile_options(pm3rrg_rdv4_hardnested_avx2 PRIVATE -Wall -Werror -O3)
    target_compile_options(pm3rrg_rdv4_hardnested_avx2 BEFORE PRIVATE
            -mmmx -msse2 -mavx -mavx2 -mno-avx512f)
    set_property(TARGET pm3rrg_rdv4_hardnested_avx2 PROPERTY POSITION_INDEPENDENT_CODE ON)

    target_include_directories(pm3rrg_rdv4_hardnested_avx2 PRIVATE
            ../../common
            ../../include
            ../src)

    ## x86 / AVX512
    add_library(pm3rrg_rdv4_hardnested_avx512 OBJECT
            hardnested/hardnested_bf_core.c
            hardnested/hardnested_bitarray_core.c)

    target_compile_options(pm3rrg_rdv4_hardnested_avx512 PRIVATE -Wall -Werror -O3)
    target_compile_options(pm3rrg_rdv4_hardnested_avx512 BEFORE PRIVATE
            -mmmx -msse2 -mavx -mavx2 -mavx512f)
    set_property(TARGET pm3rrg_rdv4_hardnested_avx512 PROPERTY POSITION_INDEPENDENT_CODE ON)

    target_include_directories(pm3rrg_rdv4_hardnested_avx512 PRIVATE
            ../../common
            ../../include
            ../src)

    set(SIMD_TARGETS
            $<TARGET_OBJECTS:pm3rrg_rdv4_hardnested_mmx>
            $<TARGET_OBJECTS:pm3rrg_rdv4_hardnested_sse2>
            $<TARGET_OBJECTS:pm3rrg_rdv4_hardnested_avx>
            $<TARGET_OBJECTS:pm3rrg_rdv4_hardnested_avx2>
            $<TARGET_OBJECTS:pm3rrg_rdv4_hardnested_avx512>)
elseif ("${CMAKE_SYSTEM_PROCESSOR}" IN_LIST ARM64_CPUS)
    message(STATUS "Building optimised arm64 binaries")

    ## arm64 / NEON
    add_library(pm3rrg_rdv4_hardnested_neon OBJECT
            hardnested/hardnested_bf_core.c
            hardnested/hardnested_bitarray_core.c)

    target_compile_options(pm3rrg_rdv4_hardnested_neon PRIVATE -Wall -Werror -O3)
    set_property(TARGET pm3rrg_rdv4_hardnested_neon PROPERTY POSITION_INDEPENDENT_CODE ON)

    target_include_directories(pm3rrg_rdv4_hardnested_neon PRIVATE
            ../../common
            ../../include
            ../src)

    set(SIMD_TARGETS
            $<TARGET_OBJECTS:pm3rrg_rdv4_hardnested_neon>)
elseif ("${CMAKE_SYSTEM_PROCESSOR}" IN_LIST ARM32_CPUS)
    message(STATUS "Building optimised arm binaries")

    ## arm64 / NEON
    add_library(pm3rrg_rdv4_hardnested_neon OBJECT
            hardnested/hardnested_bf_core.c
            hardnested/hardnested_bitarray_core.c)

    target_compile_options(pm3rrg_rdv4_hardnested_neon PRIVATE -Wall -Werror -O3)
    target_compile_options(pm3rrg_rdv4_hardnested_neon BEFORE PRIVATE
            -mfpu=neon)
    set_property(TARGET pm3rrg_rdv4_hardnested_neon PROPERTY POSITION_INDEPENDENT_CODE ON)

    target_include_directories(pm3rrg_rdv4_hardnested_neon PRIVATE
            ../../common
            ../../include
            ../src)

    set(SIMD_TARGETS
            $<TARGET_OBJECTS:pm3rrg_rdv4_hardnested_neon>)
else ()
    message(STATUS "Not building optimised targets")
    set(SIMD_TARGETS)
endif ()

add_library(pm3rrg_rdv4_hardnested STATIC
        hardnested/hardnested_bruteforce.c
        $<TARGET_OBJECTS:pm3rrg_rdv4_hardnested_nosimd>
        ${SIMD_TARGETS})
target_compile_options(pm3rrg_rdv4_hardnested PRIVATE -Wall -Werror -O3)
set_property(TARGET pm3rrg_rdv4_hardnested PROPERTY POSITION_INDEPENDENT_CODE ON)
target_include_directories(pm3rrg_rdv4_hardnested PRIVATE
        ../../common
        ../../include
        ../include
        ../src
        jansson)
target_include_directories(pm3rrg_rdv4_hardnested INTERFACE hardnested)
