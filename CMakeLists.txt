cmake_minimum_required(VERSION 3.10)
project(Crust LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/build)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/build)

set(_CRT_SECURE_NO_WARNINGS)
add_library(crust SHARED
    src/CrustAllocator.cpp
    src/CrustShadow.cpp
    src/CrustQuarantine.cpp
    src/CrustCommon.hpp
)
target_include_directories(crust PUBLIC ${CMAKE_SOURCE_DIR}/src)

target_link_libraries(crust PUBLIC dl)

add_executable(test_program test/test_program.cpp)
#target_link_libraries(test_program PRIVATE crust)

add_executable(test_overflow test/test_overflow.cpp)
#target_link_libraries(test_overflow PRIVATE crust)

add_executable(test_stress test/test_stress.cpp)
#target_link_libraries(test_stress PRIVATE crust)

add_executable(test_uaf test/test_uaf.cpp)
#target_link_libraries(test_uaf PRIVATE crust)

add_executable(test_double_free test/test_double_free.cpp)
#target_link_libraries(test_double_free PRIVATE crust)

add_executable(test_invalid_free test/test_invalid_free.cpp)
#target_link_libraries(test_invalid_free PRIVATE crust)

if (MSVC)
    target_compile_options(crust PRIVATE /W4)
else()
    target_compile_options(crust PRIVATE -Wall -Wextra -pedantic)
endif()
