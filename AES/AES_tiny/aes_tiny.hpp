#pragma once
#include <stdint.h>
#include <string.h>
#include "AES_base.hpp"

#define AES_BLOCK_SIZE 16
#define AES_256_KEY_SIZE 32
#define AES_256_NUM_ROUNDS 14
#define AES_256_EXPANDED_KEY_SIZE (4 * (AES_256_NUM_ROUNDS + 1) * 4) // 240 bytes

class AES_tiny : public AES_base {
private:
    typedef struct {
        uint8_t round_keys[AES_256_EXPANDED_KEY_SIZE];
        uint8_t sbox[256];
        uint8_t inv_sbox[256];
    } AES256_CTX;

    AES256_CTX ctx;

    static uint8_t xtime(uint8_t x) {
        return (x << 1) ^ ((x >> 7) * 0x1B);
    }

    static uint8_t gf_mul(uint8_t a, uint8_t b) {
        uint8_t res = 0;
        for (int i = 0; i < 8; ++i) {
            if (b & 1)
                res ^= a;
            bool hi = (a & 0x80);
            a <<= 1;
            if (hi)
                a ^= 0x1B;
            b >>= 1;
        }
        return res;
    }

    static uint8_t gf_pow(uint8_t a, uint8_t n) {
        uint8_t res = 1;
        while (n) {
            if (n & 1)
                res = gf_mul(res, a);
            a = gf_mul(a, a);
            n >>= 1;
        }
        return res;
    }

    static uint8_t gf_inv(uint8_t a) {
        if (a == 0) return 0;
        return gf_pow(a, 254); // a^(2^8 - 2) = a^-1 in GF(2^8)
    }

    static uint8_t affine(uint8_t a) {
        uint8_t res = a;
        for (int i = 0; i < 4; ++i)
            a = (a << 1) | (a >> 7), res ^= a;
        return res ^ 0x63;
    }

    void initialize_sboxes() {
        for (int i = 0; i < 256; ++i) {
            uint8_t inv = gf_inv(i);
            ctx.sbox[i] = affine(inv);
        }
        for (int i = 0; i < 256; ++i)
            ctx.inv_sbox[ctx.sbox[i]] = i;
    }


    static void add_round_key(uint8_t* state, const uint8_t* round_key) {
        for (int i = 0; i < AES_BLOCK_SIZE; ++i)
            state[i] ^= round_key[i];
    }

    void sub_bytes(uint8_t* state) {
        for (int i = 0; i < AES_BLOCK_SIZE; ++i)
            state[i] = ctx.sbox[state[i]];
    }

    void inv_sub_bytes(uint8_t* state) {
        for (int i = 0; i < AES_BLOCK_SIZE; ++i)
            state[i] = ctx.inv_sbox[state[i]];
    }

    static void shift_rows(uint8_t* state) {
        uint8_t tmp;
        tmp = state[1];
        state[1] = state[5];
        state[5] = state[9];
        state[9] = state[13];
        state[13] = tmp;
        tmp = state[2];
        state[2] = state[10];
        state[10] = tmp;
        tmp = state[6];
        state[6] = state[14];
        state[14] = tmp;
        tmp = state[3];
        state[3] = state[15];
        state[15] = state[11];
        state[11] = state[7];
        state[7] = tmp;
    }

    static void inv_shift_rows(uint8_t* state) {
        uint8_t tmp;
        tmp = state[13];
        state[13] = state[9];
        state[9] = state[5];
        state[5] = state[1];
        state[1] = tmp;
        tmp = state[2];
        state[2] = state[10];
        state[10] = tmp;
        tmp = state[6];
        state[6] = state[14];
        state[14] = tmp;
        tmp = state[3];
        state[3] = state[7];
        state[7] = state[11];
        state[11] = state[15];
        state[15] = tmp;
    }

    static void mix_columns(uint8_t* state) {
        for (int i = 0; i < 4; ++i) {
            uint8_t* col = state + i * 4;
            uint8_t t = col[0] ^ col[1] ^ col[2] ^ col[3];
            uint8_t tmp = col[0];
            col[0] ^= t ^ xtime(col[0] ^ col[1]);
            col[1] ^= t ^ xtime(col[1] ^ col[2]);
            col[2] ^= t ^ xtime(col[2] ^ col[3]);
            col[3] ^= t ^ xtime(col[3] ^ tmp);
        }
    }

    static uint8_t mul(uint8_t a, uint8_t b) {
        uint8_t result = 0;
        while (b) {
            if (b & 1) result ^= a;
            a = xtime(a);
            b >>= 1;
        }
        return result;
    }

    static void inv_mix_columns(uint8_t* state) {
        for (int i = 0; i < 4; ++i) {
            uint8_t* col = state + i * 4;
            uint8_t a0 = col[0], a1 = col[1], a2 = col[2], a3 = col[3];
            col[0] = mul(a0, 0x0e) ^ mul(a1, 0x0b) ^ mul(a2, 0x0d) ^ mul(a3, 0x09);
            col[1] = mul(a0, 0x09) ^ mul(a1, 0x0e) ^ mul(a2, 0x0b) ^ mul(a3, 0x0d);
            col[2] = mul(a0, 0x0d) ^ mul(a1, 0x09) ^ mul(a2, 0x0e) ^ mul(a3, 0x0b);
            col[3] = mul(a0, 0x0b) ^ mul(a1, 0x0d) ^ mul(a2, 0x09) ^ mul(a3, 0x0e);
        }
    }

    void aes256_key_expansion(const uint8_t* key) {
        uint8_t temp[4];
        memcpy(ctx.round_keys, key, 32);

        uint8_t rcon = 1;
        for (int i = 8; i < 60; ++i) {
            memcpy(temp, ctx.round_keys + 4 * (i - 1), 4);
            if (i % 8 == 0) {
                uint8_t t = temp[0];
                temp[0] = ctx.sbox[temp[1]];
                temp[1] = ctx.sbox[temp[2]];
                temp[2] = ctx.sbox[temp[3]];
                temp[3] = ctx.sbox[t];
                temp[0] ^= rcon;
                rcon = (rcon << 1) ^ (rcon & 0x80 ? 0x1B : 0x00);
            } else if (i % 8 == 4) {
                temp[0] = ctx.sbox[temp[0]];
                temp[1] = ctx.sbox[temp[1]];
                temp[2] = ctx.sbox[temp[2]];
                temp[3] = ctx.sbox[temp[3]];
            }
            for (int j = 0; j < 4; ++j)
                ctx.round_keys[4*i + j] = ctx.round_keys[4*(i-8) + j] ^ temp[j];
        }
    }

    void aes256_encrypt_block(uint8_t* block) {
        add_round_key(block, ctx.round_keys);
        for (int round = 1; round < AES_256_NUM_ROUNDS; ++round) {
            sub_bytes(block);
            shift_rows(block);
            mix_columns(block);
            add_round_key(block, ctx.round_keys + round * AES_BLOCK_SIZE);
        }
        sub_bytes(block);
        shift_rows(block);
        add_round_key(block, ctx.round_keys + AES_256_NUM_ROUNDS * AES_BLOCK_SIZE);
    }

    void aes256_decrypt_block(uint8_t* block) {
        add_round_key(block, ctx.round_keys + AES_256_NUM_ROUNDS * AES_BLOCK_SIZE);
        for (int round = AES_256_NUM_ROUNDS - 1; round > 0; --round) {
            inv_shift_rows(block);
            inv_sub_bytes(block);
            add_round_key(block, ctx.round_keys + round * AES_BLOCK_SIZE);
            inv_mix_columns(block);
        }
        inv_shift_rows(block);
        inv_sub_bytes(block);
        add_round_key(block, ctx.round_keys);
    }

    static void increment_counter(uint8_t* counter) {
        for (int i = AES_BLOCK_SIZE - 1; i >= 0; --i) {
            if (++counter[i]) break;
        }
    }

    void aes256_ctr_crypt(uint8_t* input, uint8_t* output, size_t size, uint8_t* iv) {
        uint8_t counter[AES_BLOCK_SIZE];
        uint8_t stream[AES_BLOCK_SIZE];
        memcpy(counter, iv, AES_BLOCK_SIZE);

        for (size_t i = 0; i < size; i += AES_BLOCK_SIZE) {
            memcpy(stream, counter, AES_BLOCK_SIZE);
            aes256_encrypt_block(stream);

            size_t block_len = (size - i > AES_BLOCK_SIZE) ? AES_BLOCK_SIZE : (size - i);
            for (size_t j = 0; j < block_len; ++j)
                output[i + j] = input[i + j] ^ stream[j];

            increment_counter(counter);
        }
    }

public:
    AES_tiny() { setName("AES-tiny"); }

    void init(uint8_t* key, crypto_mode mode, uint8_t* iv) override {
        AES_base::init(key, mode, iv);
        initialize_sboxes();
        aes256_key_expansion(key);
    }

    void encrypt(uint8_t* in, uint8_t* out, size_t size) override {
        switch (getCryptoMode()) {
            case AES_base::MODE_ECB_STANDARD:
                for (size_t i = 0; i < size; i += AES_BLOCK_SIZE) {
                    memcpy(out + i, in + i, AES_BLOCK_SIZE);
                    aes256_encrypt_block(out + i);
                }
                break;
            case AES_base::MODE_CTR_STANDARD:
                aes256_ctr_crypt(in, out, size, getIV());
                break;
            default:
                throw "Not implemented";
        }
    }

    void decrypt(uint8_t* in, uint8_t* out, size_t size) override {
        switch (getCryptoMode()) {
            case AES_base::MODE_ECB_STANDARD:
                for (size_t i = 0; i < size; i += AES_BLOCK_SIZE) {
                    memcpy(out + i, in + i, AES_BLOCK_SIZE);
                    aes256_decrypt_block(out + i);
                }
                break;
            case AES_base::MODE_CTR_STANDARD:
                aes256_ctr_crypt(in, out, size, getIV());
                break;
            default:
                throw "Not implemented";
        }
    }
};
