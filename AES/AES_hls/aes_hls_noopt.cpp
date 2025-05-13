#ifdef NOT_RUNNING_VITIS
    typedef struct {
        byte data;
        bool last;
    } axis_t;

    struct block_t {
        std::array<byte, 16> data;
        byte& operator[](int idx) { return data[idx]; }
        const byte& operator[](int idx) const { return data[idx]; }
    };

#else
    #include <ap_int.h>
    #include <hls_stream.h>
    #include <string.h>
    #include <ap_axi_sdata.h>
    #include <ap_int.h>
    #include <array>

    typedef ap_uint<8> byte;
    typedef ap_axiu<8, 0, 0, 1> axis_t;
    typedef ap_uint<128> block_t;
    //typedef ap_uint<256> hlskey_t;
#endif
struct round_keys_t {
    std::array<ap_uint<32>, 60> words;
    ap_uint<32>& operator[](int i) { return words[i]; }
    const ap_uint<32>& operator[](int i) const { return words[i]; }
};

struct hlskey_t {
    std::array<byte, 32> data;
    byte& operator[](int idx) { return data[idx]; }
    const byte& operator[](int idx) const { return data[idx]; }
};

// AES S-box
const byte sbox[256] = {
        0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76,
        0xCA,0x82,0xC9,0x7D,0xFA,0x59,0x47,0xF0,0xAD,0xD4,0xA2,0xAF,0x9C,0xA4,0x72,0xC0,
        0xB7,0xFD,0x93,0x26,0x36,0x3F,0xF7,0xCC,0x34,0xA5,0xE5,0xF1,0x71,0xD8,0x31,0x15,
        0x04,0xC7,0x23,0xC3,0x18,0x96,0x05,0x9A,0x07,0x12,0x80,0xE2,0xEB,0x27,0xB2,0x75,
        0x09,0x83,0x2C,0x1A,0x1B,0x6E,0x5A,0xA0,0x52,0x3B,0xD6,0xB3,0x29,0xE3,0x2F,0x84,
        0x53,0xD1,0x00,0xED,0x20,0xFC,0xB1,0x5B,0x6A,0xCB,0xBE,0x39,0x4A,0x4C,0x58,0xCF,
        0xD0,0xEF,0xAA,0xFB,0x43,0x4D,0x33,0x85,0x45,0xF9,0x02,0x7F,0x50,0x3C,0x9F,0xA8,
        0x51,0xA3,0x40,0x8F,0x92,0x9D,0x38,0xF5,0xBC,0xB6,0xDA,0x21,0x10,0xFF,0xF3,0xD2,
        0xCD,0x0C,0x13,0xEC,0x5F,0x97,0x44,0x17,0xC4,0xA7,0x7E,0x3D,0x64,0x5D,0x19,0x73,
        0x60,0x81,0x4F,0xDC,0x22,0x2A,0x90,0x88,0x46,0xEE,0xB8,0x14,0xDE,0x5E,0x0B,0xDB,
        0xE0,0x32,0x3A,0x0A,0x49,0x06,0x24,0x5C,0xC2,0xD3,0xAC,0x62,0x91,0x95,0xE4,0x79,
        0xE7,0xC8,0x37,0x6D,0x8D,0xD5,0x4E,0xA9,0x6C,0x56,0xF4,0xEA,0x65,0x7A,0xAE,0x08,
        0xBA,0x78,0x25,0x2E,0x1C,0xA6,0xB4,0xC6,0xE8,0xDD,0x74,0x1F,0x4B,0xBD,0x8B,0x8A,
        0x70,0x3E,0xB5,0x66,0x48,0x03,0xF6,0x0E,0x61,0x35,0x57,0xB9,0x86,0xC1,0x1D,0x9E,
        0xE1,0xF8,0x98,0x11,0x69,0xD9,0x8E,0x94,0x9B,0x1E,0x87,0xE9,0xCE,0x55,0x28,0xDF,
        0x8C,0xA1,0x89,0x0D,0xBF,0xE6,0x42,0x68,0x41,0x99,0x2D,0x0F,0xB0,0x54,0xBB,0x16
};

// AES inverse S-box
const byte inv_sbox[256] = {
        0x52,0x09,0x6A,0xD5,0x30,0x36,0xA5,0x38,0xBF,0x40,0xA3,0x9E,0x81,0xF3,0xD7,0xFB,
        0x7C,0xE3,0x39,0x82,0x9B,0x2F,0xFF,0x87,0x34,0x8E,0x43,0x44,0xC4,0xDE,0xE9,0xCB,
        0x54,0x7B,0x94,0x32,0xA6,0xC2,0x23,0x3D,0xEE,0x4C,0x95,0x0B,0x42,0xFA,0xC3,0x4E,
        0x08,0x2E,0xA1,0x66,0x28,0xD9,0x24,0xB2,0x76,0x5B,0xA2,0x49,0x6D,0x8B,0xD1,0x25,
        0x72,0xF8,0xF6,0x64,0x86,0x68,0x98,0x16,0xD4,0xA4,0x5C,0xCC,0x5D,0x65,0xB6,0x92,
        0x6C,0x70,0x48,0x50,0xFD,0xED,0xB9,0xDA,0x5E,0x15,0x46,0x57,0xA7,0x8D,0x9D,0x84,
        0x90,0xD8,0xAB,0x00,0x8C,0xBC,0xD3,0x0A,0xF7,0xE4,0x58,0x05,0xB8,0xB3,0x45,0x06,
        0xD0,0x2C,0x1E,0x8F,0xCA,0x3F,0x0F,0x02,0xC1,0xAF,0xBD,0x03,0x01,0x13,0x8A,0x6B,
        0x3A,0x91,0x11,0x41,0x4F,0x67,0xDC,0xEA,0x97,0xF2,0xCF,0xCE,0xF0,0xB4,0xE6,0x73,
        0x96,0xAC,0x74,0x22,0xE7,0xAD,0x35,0x85,0xE2,0xF9,0x37,0xE8,0x1C,0x75,0xDF,0x6E,
        0x47,0xF1,0x1A,0x71,0x1D,0x29,0xC5,0x89,0x6F,0xB7,0x62,0x0E,0xAA,0x18,0xBE,0x1B,
        0xFC,0x56,0x3E,0x4B,0xC6,0xD2,0x79,0x20,0x9A,0xDB,0xC0,0xFE,0x78,0xCD,0x5A,0xF4,
        0x1F,0xDD,0xA8,0x33,0x88,0x07,0xC7,0x31,0xB1,0x12,0x10,0x59,0x27,0x80,0xEC,0x5F,
        0x60,0x51,0x7F,0xA9,0x19,0xB5,0x4A,0x0D,0x2D,0xE5,0x7A,0x9F,0x93,0xC9,0x9C,0xEF,
        0xA0,0xE0,0x3B,0x4D,0xAE,0x2A,0xF5,0xB0,0xC8,0xEB,0xBB,0x3C,0x83,0x53,0x99,0x61,
        0x17,0x2B,0x04,0x7E,0xBA,0x77,0xD6,0x26,0xE1,0x69,0x14,0x63,0x55,0x21,0x0C,0x7D
};

byte gf_mul(byte a, byte b) {
    byte p = 0;
    for (int i = 0; i < 8; ++i) {
        if (b & 1) p ^= a;
        bool hi_bit_set = (a & 0x80);
        a <<= 1;
        if (hi_bit_set) a ^= 0x1b;
        b >>= 1;
    }
    return p;
}

void aes256_key_schedule(const hlskey_t &key, round_keys_t &w) {
    // Initial 8 words from the 256-bit key
    for (int i = 0; i < 8; i++) {
        w[i] = 0;
        for (int j = 0; j < 4; ++j) {
            w[i].range(8 * (3 - j) + 7, 8 * (3 - j)) = key[i * 4 + j];
        }
    }

    ap_uint<32> rcon = 0x01;
    for (int i = 8; i < 60; i++) {
        ap_uint<32> temp = w[i - 1];
        if (i % 8 == 0) {
            // Rotate
            ap_uint<32> rot = (temp << 8) | (temp >> 24);
            // Apply S-box
            for (int j = 0; j < 4; ++j) {
                rot.range(8 * j + 7, 8 * j) = sbox[rot.range(8 * j + 7, 8 * j)];
            }
            // Apply Rcon
            rot.range(31, 24) ^= rcon;
            rcon = gf_mul(rcon, 0x02); // Update Rcon
            temp = rot;
        } else if (i % 8 == 4) {
            // Apply S-box only
            for (int j = 0; j < 4; ++j) {
                temp.range(8 * j + 7, 8 * j) = sbox[temp.range(8 * j + 7, 8 * j)];
            }
        }
        w[i] = w[i - 8] ^ temp;
    }
}

void aes256_encrypt_block(const block_t &input, const ap_uint<32> w[60], block_t &output) {
    byte state[4][4];

    // Load input into state matrix
    for (int i = 0; i < 16; i++) {
        state[i % 4][i / 4] = input[i];
    }

    // Initial AddRoundKey
    for (int c = 0; c < 4; c++) {
        for (int r = 0; r < 4; r++) {
            state[r][c] ^= w[c].range(8 * (3 - r) + 7, 8 * (3 - r));
        }
    }

    // Main 13 rounds
    for (int round = 1; round < 14; round++) {
        // SubBytes
        for (int r = 0; r < 4; r++) {
            for (int c = 0; c < 4; c++) {
                state[r][c] = sbox[state[r][c]];
            }
        }

        // ShiftRows
        byte tmp[4];
        for (int r = 1; r < 4; r++) {
            for (int c = 0; c < 4; c++) tmp[c] = state[r][(c + r) % 4];
            for (int c = 0; c < 4; c++) state[r][c] = tmp[c];
        }

        // MixColumns
        for (int c = 0; c < 4; ++c) {
            byte a0 = state[0][c];
            byte a1 = state[1][c];
            byte a2 = state[2][c];
            byte a3 = state[3][c];

            state[0][c] = gf_mul(a0, 2) ^ gf_mul(a1, 3) ^ a2 ^ a3;
            state[1][c] = a0 ^ gf_mul(a1, 2) ^ gf_mul(a2, 3) ^ a3;
            state[2][c] = a0 ^ a1 ^ gf_mul(a2, 2) ^ gf_mul(a3, 3);
            state[3][c] = gf_mul(a0, 3) ^ a1 ^ a2 ^ gf_mul(a3, 2);
        }

        // AddRoundKey
        for (int c = 0; c < 4; c++) {
            for (int r = 0; r < 4; r++) {
                state[r][c] ^= w[round * 4 + c].range(8 * (3 - r) + 7, 8 * (3 - r));
            }
        }
    }

    // Final round (no MixColumns)
    for (int r = 0; r < 4; r++) {
        for (int c = 0; c < 4; c++) {
            state[r][c] = sbox[state[r][c]];
        }
    }
    for (int r = 1; r < 4; r++) {
        byte tmp[4];
        for (int c = 0; c < 4; c++) tmp[c] = state[r][(c + r) % 4];
        for (int c = 0; c < 4; c++) state[r][c] = tmp[c];
    }
    for (int c = 0; c < 4; c++) {
        for (int r = 0; r < 4; r++) {
            state[r][c] ^= w[56 + c].range(8 * (3 - r) + 7, 8 * (3 - r));
        }
    }

    // Write state to output
    for (int i = 0; i < 16; i++) {
        output[i] = state[i % 4][i / 4];
    }
}

void aes256_decrypt_block(const block_t &input, const ap_uint<32> w[60], block_t &output) {
    byte state[4][4];

    // Load input into state matrix
    for (int i = 0; i < 16; i++) {
        state[i % 4][i / 4] = input[i];
    }

    // Initial AddRoundKey (last round key)
    for (int c = 0; c < 4; c++) {
        for (int r = 0; r < 4; r++) {
            state[r][c] ^= w[56 + c].range(8 * (3 - r) + 7, 8 * (3 - r));
        }
    }

    // Main rounds (13 -> 1)
    for (int round = 13; round > 0; --round) {
        // Inverse ShiftRows
        byte tmp[4];
        for (int r = 1; r < 4; r++) {
            for (int c = 0; c < 4; c++) tmp[c] = state[r][(c - r + 4) % 4];
            for (int c = 0; c < 4; c++) state[r][c] = tmp[c];
        }

        // Inverse SubBytes
        for (int r = 0; r < 4; r++) {
            for (int c = 0; c < 4; c++) {
                state[r][c] = inv_sbox[state[r][c]];
            }
        }

        // AddRoundKey
        for (int c = 0; c < 4; c++) {
            for (int r = 0; r < 4; r++) {
                state[r][c] ^= w[round * 4 + c].range(8 * (3 - r) + 7, 8 * (3 - r));
            }
        }

        // InvMixColumns
        for (int c = 0; c < 4; ++c) {
            byte s0 = state[0][c];
            byte s1 = state[1][c];
            byte s2 = state[2][c];
            byte s3 = state[3][c];

            state[0][c] = gf_mul(s0, 0x0e) ^ gf_mul(s1, 0x0b) ^ gf_mul(s2, 0x0d) ^ gf_mul(s3, 0x09);
            state[1][c] = gf_mul(s0, 0x09) ^ gf_mul(s1, 0x0e) ^ gf_mul(s2, 0x0b) ^ gf_mul(s3, 0x0d);
            state[2][c] = gf_mul(s0, 0x0d) ^ gf_mul(s1, 0x09) ^ gf_mul(s2, 0x0e) ^ gf_mul(s3, 0x0b);
            state[3][c] = gf_mul(s0, 0x0b) ^ gf_mul(s1, 0x0d) ^ gf_mul(s2, 0x09) ^ gf_mul(s3, 0x0e);
        }
    }

    // Final round (no InvMixColumns)
    for (int r = 1; r < 4; r++) {
        byte tmp[4];
        for (int c = 0; c < 4; c++) tmp[c] = state[r][(c - r + 4) % 4];
        for (int c = 0; c < 4; c++) state[r][c] = tmp[c];
    }

    for (int r = 0; r < 4; r++) {
        for (int c = 0; c < 4; c++) {
            state[r][c] = inv_sbox[state[r][c]];
        }
    }

    for (int c = 0; c < 4; c++) {
        for (int r = 0; r < 4; r++) {
            state[r][c] ^= w[c].range(8 * (3 - r) + 7, 8 * (3 - r));
        }
    }

    // Store state to output
    for (int i = 0; i < 16; i++) {
        output[i] = state[i % 4][i / 4];
    }
}

void aes256_ctr_encrypt_stream(
		hls::stream<axis_t>& in_stream,
		hls::stream<axis_t>& out_stream,
        const hlskey_t& key,
        block_t iv,
        int num_blocks
) {
#pragma HLS INTERFACE axis port=in_stream
#pragma HLS INTERFACE axis port=out_stream
#pragma HLS INTERFACE s_axilite port=key bundle=control
#pragma HLS INTERFACE s_axilite port=iv bundle=control
#pragma HLS INTERFACE s_axilite port=num_blocks bundle=control
#pragma HLS INTERFACE s_axilite port=return bundle=control

    round_keys_t round_keys;
    aes256_key_schedule(key, round_keys);

    for (int block = 0; block < num_blocks; ++block) {
        block_t ctr_block = iv;
        block_t keystream;
        aes256_encrypt_block(ctr_block, round_keys.words.data(), keystream);

        axis_t input_word, output_word;
        for (int i = 0; i < 16; ++i) {
#pragma HLS PIPELINE II=1
            input_word = in_stream.read();
            output_word.data = input_word.data ^ keystream[i];
            output_word.last = (block == num_blocks - 1 && i == 15);
            out_stream.write(output_word);
        }

        // Increment 64-bit counter (lower half of IV)
        for (int i = 15; i >= 8; --i) {
#pragma HLS UNROLL
            iv[i] = iv[i] + 1;
            if (iv[i] != 0) break;
        }
    }
}

void aes256_ecb_encrypt_stream(
		hls::stream<axis_t>& in_stream,
		hls::stream<axis_t>& out_stream,
        const hlskey_t& key,
        int num_blocks
) {
#pragma HLS INTERFACE axis port=in_stream
#pragma HLS INTERFACE axis port=out_stream
#pragma HLS INTERFACE s_axilite port=key bundle=control
#pragma HLS INTERFACE s_axilite port=num_blocks bundle=control
#pragma HLS INTERFACE s_axilite port=return bundle=control

    round_keys_t round_keys;
    aes256_key_schedule(key, round_keys);

    for (int block = 0; block < num_blocks; ++block) {
        block_t input_block, output_block;
        axis_t word;

        // Read one block from stream
        for (int i = 0; i < 16; ++i) {
#pragma HLS PIPELINE II=1
            word = in_stream.read();
            input_block[i] = word.data;
        }

        // Encrypt the block
        aes256_encrypt_block(input_block, round_keys.words.data(), output_block);

        // Write encrypted block to output stream
        for (int i = 0; i < 16; ++i) {
#pragma HLS PIPELINE II=1
            axis_t out_word;
            out_word.data = output_block[i];
            out_word.last = (block == num_blocks - 1 && i == 15);  // Mark last byte of last block
            out_stream.write(out_word);
        }
    }
}

void aes256_ecb_decrypt_stream(
		hls::stream<axis_t>& in_stream,
		hls::stream<axis_t>& out_stream,
        const hlskey_t& key,
        int num_blocks
) {
#pragma HLS INTERFACE axis port=in_stream
#pragma HLS INTERFACE axis port=out_stream
#pragma HLS INTERFACE s_axilite port=key bundle=control
#pragma HLS INTERFACE s_axilite port=num_blocks bundle=control
#pragma HLS INTERFACE s_axilite port=return bundle=control

    round_keys_t round_keys;
    aes256_key_schedule(key, round_keys);

    for (int block = 0; block < num_blocks; ++block) {
        block_t input_block, output_block;
        axis_t word;

        // Read 16-byte block from stream
        for (int i = 0; i < 16; ++i) {
#pragma HLS PIPELINE II=1
            word = in_stream.read();
            input_block[i] = word.data;
        }

        // Decrypt block
        aes256_decrypt_block(input_block, round_keys.words.data(), output_block);

        // Write 16-byte output block to stream
        for (int i = 0; i < 16; ++i) {
#pragma HLS PIPELINE II=1
            axis_t out_word;
            out_word.data = output_block[i];
            out_word.last = (block == num_blocks - 1 && i == 15);  // Set TLAST
            out_stream.write(out_word);
        }
    }
}



