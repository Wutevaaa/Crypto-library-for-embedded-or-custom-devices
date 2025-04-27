#pragma once

#include <aes_small.hpp>
#include <aes_tiny.hpp> // for small mcus
#include <aes_cortexm.hpp> // for arm cortex
#include <aes_ni.hpp> // for x86 with AES-NI extensions
#include <aes_ni_sse.hpp> // fox x86 with AES-NI and SSE4/AVX extensions
#include <aes_ni_avx2.hpp> // fox x86 with AES-NI and AVX2 extensions

#include <aes_ni_omp.hpp> // for x86 with AES-NI extensions
#include <aes_bitsliced_sse.hpp>

