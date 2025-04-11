cmake_minimum_required(VERSION 3.20)
project(cryptoselect)

set(CMAKE_CXX_STANDARD 14)

include_directories(AES)
include_directories(AES/AES_tiny)
include_directories(AES/AES_cortexm)

include_directories(.)

add_executable(cryptoselect
        AES/aes.hpp
        AES/AES_base/AES_base.hpp
        AES/AES_tiny/aes.c
        main.cpp Utils.hpp AES/AES_bitsliced/aes_bitsliced.hpp AES/AES_bitsliced/key_schedule.c AES/AES_bitsliced/bs.hpp)
