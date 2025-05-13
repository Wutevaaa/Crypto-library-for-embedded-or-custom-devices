#pragma once
#include <wmmintrin.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "AES_base.hpp"

class AES_ni_sse : public AES_base {
private:
    typedef struct {
        __m128i enc_keys[AES_256_NUM_ROUNDS + 1];
        __m128i dec_keys[AES_256_NUM_ROUNDS + 1];
    } AES256_KEY;

    AES256_KEY aeskey;

    // Helper macro to expand two rounds at a time
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

    void aes256_key_schedule(const uint8_t *user_key, AES256_KEY *key) {
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

    inline void increment_ctr32(__m128i &ctr) {
        alignas(16) uint8_t tmp[16];
        _mm_store_si128(reinterpret_cast<__m128i*>(tmp), ctr);

        uint32_t counter = (tmp[12] << 24) | (tmp[13] << 16) | (tmp[14] << 8) | (tmp[15]);
        counter += 1;
        tmp[12] = (counter >> 24) & 0xFF;
        tmp[13] = (counter >> 16) & 0xFF;
        tmp[14] = (counter >> 8) & 0xFF;
        tmp[15] = counter & 0xFF;

        ctr = _mm_load_si128(reinterpret_cast<const __m128i*>(tmp));
    }

    void aes256_ecb_encrypt_parallel(const AES256_KEY *key, const uint8_t *input, uint8_t *output, size_t blocks) {
        size_t i = 0;
        for (; i + 3 < blocks; i += 4) {
            __m128i block0 = _mm_loadu_si128((const __m128i*)(input + (i + 0) * AES_BLOCK_SIZE_BYTES));
            __m128i block1 = _mm_loadu_si128((const __m128i*)(input + (i + 1) * AES_BLOCK_SIZE_BYTES));
            __m128i block2 = _mm_loadu_si128((const __m128i*)(input + (i + 2) * AES_BLOCK_SIZE_BYTES));
            __m128i block3 = _mm_loadu_si128((const __m128i*)(input + (i + 3) * AES_BLOCK_SIZE_BYTES));

            block0 = _mm_xor_si128(block0, key->enc_keys[0]);
            block1 = _mm_xor_si128(block1, key->enc_keys[0]);
            block2 = _mm_xor_si128(block2, key->enc_keys[0]);
            block3 = _mm_xor_si128(block3, key->enc_keys[0]);

            for (int r = 1; r < AES_256_NUM_ROUNDS; ++r) {
                block0 = _mm_aesenc_si128(block0, key->enc_keys[r]);
                block1 = _mm_aesenc_si128(block1, key->enc_keys[r]);
                block2 = _mm_aesenc_si128(block2, key->enc_keys[r]);
                block3 = _mm_aesenc_si128(block3, key->enc_keys[r]);
            }

            block0 = _mm_aesenclast_si128(block0, key->enc_keys[AES_256_NUM_ROUNDS]);
            block1 = _mm_aesenclast_si128(block1, key->enc_keys[AES_256_NUM_ROUNDS]);
            block2 = _mm_aesenclast_si128(block2, key->enc_keys[AES_256_NUM_ROUNDS]);
            block3 = _mm_aesenclast_si128(block3, key->enc_keys[AES_256_NUM_ROUNDS]);

            _mm_storeu_si128((__m128i*)(output + (i + 0) * AES_BLOCK_SIZE_BYTES), block0);
            _mm_storeu_si128((__m128i*)(output + (i + 1) * AES_BLOCK_SIZE_BYTES), block1);
            _mm_storeu_si128((__m128i*)(output + (i + 2) * AES_BLOCK_SIZE_BYTES), block2);
            _mm_storeu_si128((__m128i*)(output + (i + 3) * AES_BLOCK_SIZE_BYTES), block3);
        }

        for (; i < blocks; ++i) {
            __m128i block = _mm_loadu_si128((const __m128i*)(input + i * AES_BLOCK_SIZE_BYTES));

            block = _mm_xor_si128(block, key->enc_keys[0]);
            for (int r = 1; r < AES_256_NUM_ROUNDS; ++r)
                block = _mm_aesenc_si128(block, key->enc_keys[r]);
            block = _mm_aesenclast_si128(block, key->enc_keys[AES_256_NUM_ROUNDS]);

            _mm_storeu_si128((__m128i*)(output + i * AES_BLOCK_SIZE_BYTES), block);
        }
    }

    void aes256_ecb_decrypt_parallel(const AES256_KEY *key, const uint8_t *input, uint8_t *output, size_t blocks) {
        size_t i = 0;
        for (; i + 3 < blocks; i += 4) {
            __m128i block0 = _mm_loadu_si128((const __m128i*)(input + (i + 0) * AES_BLOCK_SIZE_BYTES));
            __m128i block1 = _mm_loadu_si128((const __m128i*)(input + (i + 1) * AES_BLOCK_SIZE_BYTES));
            __m128i block2 = _mm_loadu_si128((const __m128i*)(input + (i + 2) * AES_BLOCK_SIZE_BYTES));
            __m128i block3 = _mm_loadu_si128((const __m128i*)(input + (i + 3) * AES_BLOCK_SIZE_BYTES));

            block0 = _mm_xor_si128(block0, key->dec_keys[0]);
            block1 = _mm_xor_si128(block1, key->dec_keys[0]);
            block2 = _mm_xor_si128(block2, key->dec_keys[0]);
            block3 = _mm_xor_si128(block3, key->dec_keys[0]);

            for (int r = 1; r < AES_256_NUM_ROUNDS; ++r) {
                block0 = _mm_aesdec_si128(block0, key->dec_keys[r]);
                block1 = _mm_aesdec_si128(block1, key->dec_keys[r]);
                block2 = _mm_aesdec_si128(block2, key->dec_keys[r]);
                block3 = _mm_aesdec_si128(block3, key->dec_keys[r]);
            }

            block0 = _mm_aesdeclast_si128(block0, key->dec_keys[AES_256_NUM_ROUNDS]);
            block1 = _mm_aesdeclast_si128(block1, key->dec_keys[AES_256_NUM_ROUNDS]);
            block2 = _mm_aesdeclast_si128(block2, key->dec_keys[AES_256_NUM_ROUNDS]);
            block3 = _mm_aesdeclast_si128(block3, key->dec_keys[AES_256_NUM_ROUNDS]);

            _mm_storeu_si128((__m128i*)(output + (i + 0) * AES_BLOCK_SIZE_BYTES), block0);
            _mm_storeu_si128((__m128i*)(output + (i + 1) * AES_BLOCK_SIZE_BYTES), block1);
            _mm_storeu_si128((__m128i*)(output + (i + 2) * AES_BLOCK_SIZE_BYTES), block2);
            _mm_storeu_si128((__m128i*)(output + (i + 3) * AES_BLOCK_SIZE_BYTES), block3);
        }

        for (; i < blocks; ++i) {
            __m128i block = _mm_loadu_si128((const __m128i*)(input + i * AES_BLOCK_SIZE_BYTES));

            block = _mm_xor_si128(block, key->dec_keys[0]);
            for (int r = 1; r < AES_256_NUM_ROUNDS; ++r)
                block = _mm_aesdec_si128(block, key->dec_keys[r]);
            block = _mm_aesdeclast_si128(block, key->dec_keys[AES_256_NUM_ROUNDS]);

            _mm_storeu_si128((__m128i*)(output + i * AES_BLOCK_SIZE_BYTES), block);
        }
    }

    void aes256_ctr_encrypt_parallel(const AES256_KEY *key, const uint8_t *input, uint8_t *output, size_t blocks, const uint8_t iv[16]) {
        __m128i ctr = _mm_loadu_si128((const __m128i*)iv);
        size_t i = 0;

        for (; i + 3 < blocks; i += 4) {
            __m128i ctr0 = ctr;
            increment_ctr32(ctr);
            __m128i ctr1 = ctr;
            increment_ctr32(ctr);
            __m128i ctr2 = ctr;
            increment_ctr32(ctr);
            __m128i ctr3 = ctr;
            increment_ctr32(ctr);

            __m128i stream0 = _mm_xor_si128(ctr0, key->enc_keys[0]);
            __m128i stream1 = _mm_xor_si128(ctr1, key->enc_keys[0]);
            __m128i stream2 = _mm_xor_si128(ctr2, key->enc_keys[0]);
            __m128i stream3 = _mm_xor_si128(ctr3, key->enc_keys[0]);

            for (int r = 1; r < AES_256_NUM_ROUNDS; ++r) {
                stream0 = _mm_aesenc_si128(stream0, key->enc_keys[r]);
                stream1 = _mm_aesenc_si128(stream1, key->enc_keys[r]);
                stream2 = _mm_aesenc_si128(stream2, key->enc_keys[r]);
                stream3 = _mm_aesenc_si128(stream3, key->enc_keys[r]);
            }

            stream0 = _mm_aesenclast_si128(stream0, key->enc_keys[AES_256_NUM_ROUNDS]);
            stream1 = _mm_aesenclast_si128(stream1, key->enc_keys[AES_256_NUM_ROUNDS]);
            stream2 = _mm_aesenclast_si128(stream2, key->enc_keys[AES_256_NUM_ROUNDS]);
            stream3 = _mm_aesenclast_si128(stream3, key->enc_keys[AES_256_NUM_ROUNDS]);

            __m128i pt0 = _mm_loadu_si128((const __m128i*)(input + (i + 0) * AES_BLOCK_SIZE_BYTES));
            __m128i pt1 = _mm_loadu_si128((const __m128i*)(input + (i + 1) * AES_BLOCK_SIZE_BYTES));
            __m128i pt2 = _mm_loadu_si128((const __m128i*)(input + (i + 2) * AES_BLOCK_SIZE_BYTES));
            __m128i pt3 = _mm_loadu_si128((const __m128i*)(input + (i + 3) * AES_BLOCK_SIZE_BYTES));

            __m128i ct0 = _mm_xor_si128(pt0, stream0);
            __m128i ct1 = _mm_xor_si128(pt1, stream1);
            __m128i ct2 = _mm_xor_si128(pt2, stream2);
            __m128i ct3 = _mm_xor_si128(pt3, stream3);

            _mm_storeu_si128((__m128i*)(output + (i + 0) * AES_BLOCK_SIZE_BYTES), ct0);
            _mm_storeu_si128((__m128i*)(output + (i + 1) * AES_BLOCK_SIZE_BYTES), ct1);
            _mm_storeu_si128((__m128i*)(output + (i + 2) * AES_BLOCK_SIZE_BYTES), ct2);
            _mm_storeu_si128((__m128i*)(output + (i + 3) * AES_BLOCK_SIZE_BYTES), ct3);
        }

        for (; i < blocks; ++i) {
            __m128i stream = _mm_xor_si128(ctr, key->enc_keys[0]);
            for (int r = 1; r < AES_256_NUM_ROUNDS; ++r)
                stream = _mm_aesenc_si128(stream, key->enc_keys[r]);
            stream = _mm_aesenclast_si128(stream, key->enc_keys[AES_256_NUM_ROUNDS]);

            __m128i pt = _mm_loadu_si128((const __m128i*)(input + i * AES_BLOCK_SIZE_BYTES));
            __m128i ct = _mm_xor_si128(pt, stream);

            _mm_storeu_si128((__m128i*)(output + i * AES_BLOCK_SIZE_BYTES), ct);

            increment_ctr32(ctr);
        }
    }

public:
    AES_ni_sse() {setName("AES-NI-SSE");}
    void init(const uint8_t* key, crypto_mode mode, const uint8_t* iv) override {
        AES_base::init(key, mode, iv);
        switch(mode) {
            case AES_base::MODE_ECB_INPLACE:
            case AES_base::MODE_ECB_STANDARD:
            case AES_base::MODE_CTR_INPLACE:
            case AES_base::MODE_CTR_STANDARD:
                aes256_key_schedule(key, &aeskey);
                break;
        }
    }

    void encrypt(uint8_t* in, uint8_t* out, size_t size) override {
        switch(getCryptoMode()) {
            case AES_base::MODE_ECB_STANDARD:
                aes256_ecb_encrypt_parallel(&aeskey, in, out, size / AES_BLOCK_SIZE_BYTES);
                break;
            case AES_base::MODE_CTR_STANDARD:
                aes256_ctr_encrypt_parallel(&aeskey, in, out, size / AES_BLOCK_SIZE_BYTES, getIV());
                break;
            default:
                throw "Not implemented";
        }
    }

    void decrypt(uint8_t* in, uint8_t* out, size_t size) override {
        switch(getCryptoMode()) {
            case AES_base::MODE_ECB_STANDARD:
                aes256_ecb_decrypt_parallel(&aeskey, in, out, size / AES_BLOCK_SIZE_BYTES); // decrypt = encrypt for ECB
                break;
            case AES_base::MODE_CTR_STANDARD:
                aes256_ctr_encrypt_parallel(&aeskey, in, out, size / AES_BLOCK_SIZE_BYTES, getIV());
                break;
            default:
                throw "Not implemented";
        }
    }
};
