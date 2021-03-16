# just for testing amiitool before complete migration into a lib:

#amiitool:
#gcc $(CFLAGS) \
#amiitool.c $(MYSRCS) ../../../../common/../../commonutil.c ../ui.c -lreadline -lm ../../../../common/mbedtls/libmbedtls.a \
#-o amiitool

add_library(pm3rrg_rdv4_amiibo STATIC
        amiitool/amiibo.c
        amiitool/drbg.c
        amiitool/keygen.c
)

if (NOT TARGET pm3rrg_rdv4_mbedtls)
  include(mbedtls.cmake)
endif()

target_link_libraries(pm3rrg_rdv4_amiibo PRIVATE
        m
        pm3rrg_rdv4_mbedtls)

target_compile_options(pm3rrg_rdv4_amiibo PRIVATE -Wall -Werror -O3)
set_property(TARGET pm3rrg_rdv4_amiibo PROPERTY POSITION_INDEPENDENT_CODE ON)

target_include_directories(pm3rrg_rdv4_amiibo PRIVATE amiitool
            ../../common
            ../../include
            ../src
            jansson)

target_include_directories(pm3rrg_rdv4_amiibo INTERFACE amiitool)