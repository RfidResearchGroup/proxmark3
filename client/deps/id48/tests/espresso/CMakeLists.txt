cmake_minimum_required(VERSION 3.21)

add_executable(
    id48lib_test_espresso
    main.c
    verify_espresso.c
)

target_link_libraries(id48lib_test_espresso PRIVATE id48lib)

target_include_directories(id48lib_test_espresso PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_compile_options(id48lib_test_espresso PRIVATE
    $<$<COMPILE_LANGUAGE:C>:-O0>
    $<$<COMPILE_LANGUAGE:CXX>:-O0>
)
