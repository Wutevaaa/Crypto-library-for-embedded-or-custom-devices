cmake_minimum_required(VERSION 3.20)
project(cryptoselect)

set(CMAKE_CXX_STANDARD 14)
include_directories(AES/AEStiny)
include_directories(.)

add_executable(cryptoselect AES/AEStiny/aes.c main.cpp Utils.hpp)
