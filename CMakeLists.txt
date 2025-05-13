cmake_minimum_required(VERSION 3.20)
project(clecd)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_FLAGS "-fopenmp -maes -mavx2")

include_directories(AES)
include_directories(AES/AES_base)
include_directories(AES/AES_small)
include_directories(AES/AES_tiny)
include_directories(AES/AES_cortexm)
include_directories(AES/AES_ni)
include_directories(AES/AES_bitsliced)
include_directories(AES/AES_hls)

include_directories(.)

add_executable(clecd
        Utils.hpp
        AES/AES_base/AES_base.hpp
        AES/AES_tiny/aes_tiny.hpp
        AES/AES_small/aes_small.hpp
        AES/AES_ni/aes_ni.hpp
        AES/AES_ni/aes_ni_sse.hpp
        AES/AES_ni/aes_ni_avx2.hpp
        AES/AES_bitsliced/aes_bitsliced_sse.hpp
        AES/AES_hls/aes_hls.hpp
        AES/aes.hpp
        main.cpp
        AES/AES_hls/aes_hls.hpp)

target_link_libraries(clecd gomp)