cmake_minimum_required(VERSION 3.21)

add_executable(
    id48lib_test_generator
    main.c
)

target_link_libraries(id48lib_test_generator PRIVATE id48lib)

target_compile_options(id48lib_test_generator PRIVATE
    $<$<COMPILE_LANGUAGE:C>:-O0>
)
