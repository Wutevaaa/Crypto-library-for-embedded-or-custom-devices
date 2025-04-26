#pragma once
#include <wmmintrin.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <omp.h>    // <--- add OpenMP header
#include "AES_base.hpp"

class AES_ni_omp : public AES_base {
private:
    typedef struct {
        __m128i enc_keys[AES_256_NUM_ROUNDS + 1];
        __m128i dec_keys[AES_256_NUM_ROUNDS + 1];
    } AES256_KEY;

    AES256_KEY aeskey;

    inline void increment_ctr(__m128i& ctr) {
        alignas(16) uint8_t tmp[16];
        _mm_store_si128((__m128i*)tmp, ctr);
        uint32_t counter = (tmp[12] << 24) | (tmp[13] << 16) | (tmp[14] << 8) | (tmp[15]);
        counter++;
        tmp[12] = (counter >> 24) & 0xff;
        tmp[13] = (counter >> 16) & 0xff;
        tmp[14] = (counter >> 8) & 0xff;
        tmp[15] = (counter >> 0) & 0xff;
        ctr = _mm_load_si128((__m128i*)tmp);
    }

#define EXPAND_STEP(k1, k2, rcon)                      \
    temp1 = _mm_aeskeygenassist_si128(k2, rcon);        \
    temp1 = _mm_shuffle_epi32(temp1, _MM_SHUFFLE(3,3,3,3)); \
    k1 = _mm_xor_si128(k1, _mm_slli_si128(k1, 4));      \
    k1 = _mm_xor_si128(k1, _mm_slli_si128(k1, 4));      \
    k1 = _mm_xor_si128(k1, _mm_slli_si128(k1, 4));      \
    k1 = _mm_xor_si128(k1, temp1);                      \
    key->enc_keys[idx++] = k1;                          \
    temp1 = _mm_aeskeygenassist_si128(k1, 0x00);         \
    temp1 = _mm_shuffle_epi32(temp1, _MM_SHUFFLE(2,2,2,2)); \
    k2 = _mm_xor_si128(k2, _mm_slli_si128(k2, 4));       \
    k2 = _mm_xor_si128(k2, _mm_slli_si128(k2, 4));       \
    k2 = _mm_xor_si128(k2, _mm_slli_si128(k2, 4));       \
    k2 = _mm_xor_si128(k2, temp1);                      \
    key->enc_keys[idx++] = k2;

    void aes256_key_schedule(const uint8_t* user_key, AES256_KEY* key) {
        __m128i temp1, k1, k2;
        int idx = 0;

        k1 = _mm_loadu_si128((const __m128i*)(user_key));
        k2 = _mm_loadu_si128((const __m128i*)(user_key + 16));

        key->enc_keys[idx++] = k1;
        key->enc_keys[idx++] = k2;

        EXPAND_STEP(k1, k2, 0x01);
        EXPAND_STEP(k1, k2, 0x02);
        EXPAND_STEP(k1, k2, 0x04);
        EXPAND_STEP(k1, k2, 0x08);
        EXPAND_STEP(k1, k2, 0x10);
        EXPAND_STEP(k1, k2, 0x20);
        EXPAND_STEP(k1, k2, 0x40);

        key->dec_keys[0] = key->enc_keys[AES_256_NUM_ROUNDS];
        for (int i = 1; i < AES_256_NUM_ROUNDS; ++i) {
            key->dec_keys[i] = _mm_aesimc_si128(key->enc_keys[AES_256_NUM_ROUNDS - i]);
        }
        key->dec_keys[AES_256_NUM_ROUNDS] = key->enc_keys[0];
    }

#undef EXPAND_STEP

    void aes256_ecb_encrypt(const AES256_KEY* key, const uint8_t* input, uint8_t* output, size_t blocks) {
#pragma omp parallel for
        for (size_t i = 0; i < blocks; ++i) {
            __m128i block = _mm_loadu_si128((const __m128i*)(input + i * AES_BLOCK_SIZE_BYTES));

            block = _mm_xor_si128(block, key->enc_keys[0]);
            for (int r = 1; r < AES_256_NUM_ROUNDS; ++r)
                block = _mm_aesenc_si128(block, key->enc_keys[r]);
            block = _mm_aesenclast_si128(block, key->enc_keys[AES_256_NUM_ROUNDS]);

            _mm_storeu_si128((__m128i*)(output + i * AES_BLOCK_SIZE_BYTES), block);
        }
    }

    void aes256_ecb_decrypt(const AES256_KEY* key, const uint8_t* input, uint8_t* output, size_t blocks) {
#pragma omp parallel for
        for (size_t i = 0; i < blocks; ++i) {
            __m128i block = _mm_loadu_si128((const __m128i*)(input + i * AES_BLOCK_SIZE_BYTES));

            block = _mm_xor_si128(block, key->dec_keys[0]);
            for (int r = 1; r < AES_256_NUM_ROUNDS; ++r)
                block = _mm_aesdec_si128(block, key->dec_keys[r]);
            block = _mm_aesdeclast_si128(block, key->dec_keys[AES_256_NUM_ROUNDS]);

            _mm_storeu_si128((__m128i*)(output + i * AES_BLOCK_SIZE_BYTES), block);
        }
    }

    void aes256_ctr_encrypt_nist(const AES256_KEY* key, const uint8_t* input, uint8_t* output, size_t blocks, const uint8_t iv[16]) {
        __m128i ctr_base = _mm_loadu_si128((const __m128i*)iv);

#pragma omp parallel for
        for (size_t i = 0; i < blocks; ++i) {
            __m128i ctr = ctr_base;
            uint8_t* ctr_bytes = (uint8_t*)&ctr;
            uint32_t counter = (ctr_bytes[12] << 24) | (ctr_bytes[13] << 16) | (ctr_bytes[14] << 8) | (ctr_bytes[15]);
            counter += i;
            ctr_bytes[12] = (counter >> 24) & 0xff;
            ctr_bytes[13] = (counter >> 16) & 0xff;
            ctr_bytes[14] = (counter >> 8) & 0xff;
            ctr_bytes[15] = counter & 0xff;

            __m128i stream_block = _mm_xor_si128(ctr, key->enc_keys[0]);
            for (int r = 1; r < AES_256_NUM_ROUNDS; ++r) {
                stream_block = _mm_aesenc_si128(stream_block, key->enc_keys[r]);
            }
            stream_block = _mm_aesenclast_si128(stream_block, key->enc_keys[AES_256_NUM_ROUNDS]);

            __m128i pt_block = _mm_loadu_si128((const __m128i*)(input + i * AES_BLOCK_SIZE_BYTES));
            __m128i ct_block = _mm_xor_si128(pt_block, stream_block);

            _mm_storeu_si128((__m128i*)(output + i * AES_BLOCK_SIZE_BYTES), ct_block);
        }
    }

public:
    AES_ni_omp() {setName("AES-NI-OMP");}
    void init(uint8_t* key, crypto_mode mode, uint8_t* iv) override {
        AES_base::init(key, mode, iv);
        switch (mode) {
            case AES_base::MODE_ECB_INPLACE:
            case AES_base::MODE_ECB_STANDARD:
            case AES_base::MODE_CTR_INPLACE:
            case AES_base::MODE_CTR_STANDARD:
                aes256_key_schedule(key, &aeskey);
                break;
        }
    }

    void encrypt(uint8_t* in, uint8_t* out, size_t size) override {
        size_t blocks = size / AES_BLOCK_SIZE_BYTES;
        switch (getCryptoMode()) {
            case AES_base::MODE_ECB_STANDARD:
                aes256_ecb_encrypt(&aeskey, in, out, blocks);
                break;
            case AES_base::MODE_CTR_STANDARD:
                aes256_ctr_encrypt_nist(&aeskey, in, out, blocks, getIV());
                break;
            default:
                throw "Not implemented";
        }
    }

    void decrypt(uint8_t* in, uint8_t* out, size_t size) override {
        size_t blocks = size / AES_BLOCK_SIZE_BYTES;
        switch (getCryptoMode()) {
            case AES_base::MODE_ECB_STANDARD:
                aes256_ecb_decrypt(&aeskey, in, out, blocks);
                break;
            case AES_base::MODE_CTR_STANDARD:
                aes256_ctr_encrypt_nist(&aeskey, in, out, blocks, getIV());
                break;
            default:
                throw "Not implemented";
        }
    }
};
