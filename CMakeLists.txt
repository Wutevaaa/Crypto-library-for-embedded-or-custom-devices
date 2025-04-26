cmake_minimum_required(VERSION 3.20)
project(clecd)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_FLAGS "-fopenmp -maes -mavx2")

include_directories(AES)
include_directories(AES/AES_base)
include_directories(AES/AES_tiny)
include_directories(AES/AES_cortexm)
include_directories(AES/AES_ni)

include_directories(.)

add_executable(clecd
        Utils.hpp
        AES/AES_base/AES_base.hpp
        AES/AES_tiny/aes.c
        AES/AES_bitsliced/aes_bitsliced.hpp
        AES/AES_bitsliced/key_schedule.c
        AES/AES_bitsliced/bs.hpp
        AES/AES_ni/aes_ni.hpp
        AES/aes.hpp
        main.cpp AES/AES_ni/aes_ni_sse.hpp AES/AES_ni/aes_ni_avx2.hpp)

target_link_libraries(clecd gomp)