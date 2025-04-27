#pragma once

#include <cstring>

#define AES_BLOCK_SIZE_BYTES 16
#define AES_BLOCK_SIZE_BITS 128
#define AES_256_NUM_ROUNDS 14

class AES_base {
public:
    enum crypto_mode {
        MODE_ECB_INPLACE,
        MODE_ECB_STANDARD,
        MODE_CTR_INPLACE,
        MODE_CTR_STANDARD
    } mode_t;

    virtual void init(uint8_t* key, crypto_mode mode = MODE_ECB_INPLACE, uint8_t* iv = NULL) {
        mKey = key;
        mMode = mode;
        mIV = iv;
    }

    virtual void encrypt(uint8_t* in, uint8_t* out, size_t size) = 0;
    virtual void decrypt(uint8_t* in, uint8_t* out, size_t size) = 0;

    virtual int test(uint64_t& mse, uint64_t& msd, uint64_t speedtestsize = 1024*1024*1024) {
        mse = 0;
        msd = 0;

        const uint32_t VALIDATION_TEST_SIZE = 64;

        uint8_t key[32] = {
                0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
                0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
                0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
        };

        uint8_t plaintext[VALIDATION_TEST_SIZE] = {
                0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
                0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
                0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
                0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
                0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
                0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
                0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
                0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
        };

        uint8_t expected_ecb_ciphertext[VALIDATION_TEST_SIZE] = {
                0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2, 0xa0, 0x3c,
                0x06, 0x4b, 0x5a, 0x7e, 0x3d, 0xb1, 0x81, 0xf8,
                0x59, 0x1c, 0xcb, 0x10, 0xd4, 0x10, 0xed, 0x26,
                0xdc, 0x5b, 0xa7, 0x4a, 0x31, 0x36, 0x28, 0x70,
                0xb6, 0xed, 0x21, 0xb9, 0x9c, 0xa6, 0xf4, 0xf9,
                0xf1, 0x53, 0xe7, 0xb1, 0xbe, 0xaf, 0xed, 0x1d,
                0x23, 0x30, 0x4b, 0x7a, 0x39, 0xf9, 0xf3, 0xff,
                0x06, 0x7d, 0x8d, 0x8f, 0x9e, 0x24, 0xec, 0xc7
        };

        uint8_t expected_ctr_ciphertext[VALIDATION_TEST_SIZE] = {
                0x60, 0x1e, 0xc3, 0x13, 0x77, 0x57, 0x89, 0xa5,
                0xb7, 0xa7, 0xf5, 0x04, 0xbb, 0xf3, 0xd2, 0x28,
                0xf4, 0x43, 0xe3, 0xca, 0x4d, 0x62, 0xb5, 0x9a,
                0xca, 0x84, 0xe9, 0x90, 0xca, 0xca, 0xf5, 0xc5,
                0x2b, 0x09, 0x30, 0xda, 0xa2, 0x3d, 0xe9, 0x4c,
                0xe8, 0x70, 0x17, 0xba, 0x2d, 0x84, 0x98, 0x8d,
                0xdf, 0xc9, 0xc5, 0x8d, 0xb6, 0x7a, 0xad, 0xa6,
                0x13, 0xc2, 0xdd, 0x08, 0x45, 0x79, 0x41, 0xa6
        };

        uint8_t ciphertext[VALIDATION_TEST_SIZE] = {0};
        uint8_t decrypted[VALIDATION_TEST_SIZE] = {0};
        bool encrypted_ok;
        bool decrypted_ok;

        //ECB test
        init(key, MODE_ECB_STANDARD, NULL);
        encrypt(plaintext, ciphertext, VALIDATION_TEST_SIZE);
        decrypt(ciphertext, decrypted, VALIDATION_TEST_SIZE);

        std::cout << "AES-256 ECB NIST testing " << getName();
        encrypted_ok = std::memcmp(ciphertext, expected_ecb_ciphertext, sizeof(VALIDATION_TEST_SIZE)) == 0;
        decrypted_ok = std::memcmp(decrypted, plaintext, sizeof(plaintext)) == 0;
        std::cout << (encrypted_ok && decrypted_ok ? " PASSED\n" : " FAILED\n");

        //print_hex("ECB plaintext         ", plaintext, VALIDATION_TEST_SIZE);
        //print_hex("ECB ciphertext        ", ciphertext, VALIDATION_TEST_SIZE);
        //print_hex("ECB expectedciphertext", expected_ecb_ciphertext, VALIDATION_TEST_SIZE);
        //print_hex("ECB decrypted         ", decrypted, VALIDATION_TEST_SIZE);

        //CTR test
        uint8_t iv[16] = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff}; // IV for test
        init(key, MODE_CTR_STANDARD, iv);
        encrypt(plaintext, ciphertext, VALIDATION_TEST_SIZE);
        decrypt(ciphertext, decrypted, VALIDATION_TEST_SIZE);

        std::cout << "AES-256 CTR NIST testing " << getName();
        encrypted_ok = std::memcmp(ciphertext, expected_ctr_ciphertext, sizeof(VALIDATION_TEST_SIZE)) == 0;
        decrypted_ok = std::memcmp(decrypted, plaintext, sizeof(plaintext)) == 0;
        std::cout << (encrypted_ok && decrypted_ok ? " PASSED\n" : " FAILED\n");

        //print_hex("CTR plaintext", plaintext, VALIDATION_TEST_SIZE);
        //print_hex("CTR ciphertext", ciphertext, VALIDATION_TEST_SIZE);
        //print_hex("CTR expectedciphertext", expected_ctr_ciphertext, VALIDATION_TEST_SIZE);
        //print_hex("CTR decrypted", decrypted, VALIDATION_TEST_SIZE);

        uint8_t* splaintext = new uint8_t[speedtestsize];
        uint8_t* sciphertext = new uint8_t[speedtestsize];

        auto start = Utils::getMillis();
        encrypt(splaintext, sciphertext, speedtestsize);
        auto stop = Utils::getMillis();
        if (encrypted_ok) mse = stop - start;

        start = Utils::getMillis();
        decrypt(sciphertext, splaintext, speedtestsize);
        stop = Utils::getMillis();
        if (decrypted_ok) msd = stop - start;

        delete[] splaintext;
        delete[] sciphertext;

        return 1;
    }

    virtual int testblocks(uint64_t& mse, uint64_t& msd, uint64_t speedtestsize = 1024*1024*1024) {
        mse = 0;
        msd = 0;

        const uint32_t VALIDATION_TEST_SIZE = 64;

        uint8_t key[32] = {
                0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
                0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
                0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
        };

        uint8_t plaintext[VALIDATION_TEST_SIZE] = {
                0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
                0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
                0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
                0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
                0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
                0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
                0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
                0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
        };

        uint8_t expected_ecb_ciphertext[VALIDATION_TEST_SIZE] = {
                0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2, 0xa0, 0x3c,
                0x06, 0x4b, 0x5a, 0x7e, 0x3d, 0xb1, 0x81, 0xf8,
                0x59, 0x1c, 0xcb, 0x10, 0xd4, 0x10, 0xed, 0x26,
                0xdc, 0x5b, 0xa7, 0x4a, 0x31, 0x36, 0x28, 0x70,
                0xb6, 0xed, 0x21, 0xb9, 0x9c, 0xa6, 0xf4, 0xf9,
                0xf1, 0x53, 0xe7, 0xb1, 0xbe, 0xaf, 0xed, 0x1d,
                0x23, 0x30, 0x4b, 0x7a, 0x39, 0xf9, 0xf3, 0xff,
                0x06, 0x7d, 0x8d, 0x8f, 0x9e, 0x24, 0xec, 0xc7
        };

        uint8_t expected_ctr_ciphertext[VALIDATION_TEST_SIZE] = {
                0x60, 0x1e, 0xc3, 0x13, 0x77, 0x57, 0x89, 0xa5,
                0xb7, 0xa7, 0xf5, 0x04, 0xbb, 0xf3, 0xd2, 0x28,
                0xf4, 0x43, 0xe3, 0xca, 0x4d, 0x62, 0xb5, 0x9a,
                0xca, 0x84, 0xe9, 0x90, 0xca, 0xca, 0xf5, 0xc5,
                0x2b, 0x09, 0x30, 0xda, 0xa2, 0x3d, 0xe9, 0x4c,
                0xe8, 0x70, 0x17, 0xba, 0x2d, 0x84, 0x98, 0x8d,
                0xdf, 0xc9, 0xc5, 0x8d, 0xb6, 0x7a, 0xad, 0xa6,
                0x13, 0xc2, 0xdd, 0x08, 0x45, 0x79, 0x41, 0xa6
        };

        uint8_t input[16 * 8] = {0};
        uint8_t output[16 * 8] = {0};
        uint8_t decrypted[16 * 8] = {0};

        // Fill 8 copies of plaintext
        for (int i = 0; i < 8; ++i)
            memcpy(input + i * 16, plaintext, 16);

        init((uint8_t*)key, AES_base::MODE_ECB_STANDARD, nullptr);
        encrypt(input, output, sizeof(input));

        bool encrypted_ok = true;
        for (int i = 0; i < 8; ++i) {
            if (memcmp(output + i * 16, expected_ecb_ciphertext, 16) != 0) {
                encrypted_ok = false;
                break;
            }
        }

        if (encrypted_ok) {
            std::cout << "✅ AES Bitslice Encryption Passed!" << std::endl;
        } else {
            std::cout << "❌ AES Bitslice Encryption Failed!" << std::endl;
        }

        // Now test decryption
        decrypt(output, decrypted, sizeof(output));

        bool decrypted_ok = true;
        for (int i = 0; i < 8; ++i) {
            if (memcmp(decrypted + i * 16, plaintext, 16) != 0) {
                decrypted_ok = false;
                break;
            }
        }

        if (decrypted_ok) {
            std::cout << "✅ AES Bitslice Decryption Passed!" << std::endl;
        } else {
            std::cout << "❌ AES Bitslice Decryption Failed!" << std::endl;
        }

        // Benchmark encryption
        uint8_t* splaintext = new uint8_t[speedtestsize];
        uint8_t* sciphertext = new uint8_t[speedtestsize];

        auto start = Utils::getMillis();
        encrypt(splaintext, sciphertext, speedtestsize);
        auto stop = Utils::getMillis();
        if (encrypted_ok) mse = stop - start;

        start = Utils::getMillis();
        decrypt(sciphertext, splaintext, speedtestsize);
        stop = Utils::getMillis();
        if (decrypted_ok) msd = stop - start;

        delete[] splaintext;
        delete[] sciphertext;

        return 0;
    }

    void print_hex(const char *label, const uint8_t *data, size_t len) {
        printf("%s: ", label);
        for (size_t i = 0; i < len; ++i)
            printf("%02x ", data[i]);
        printf("\n");
    }

    std::string getName() {
        return mName;
    }

    void setName(const char* name) {
        mName = name;
    }

protected:
    crypto_mode getCryptoMode() { return mMode; }
    uint8_t* getKey() { return mKey; }
    uint8_t* getIV() { return mIV; }
    std::string mName = "N/A";

private:
    crypto_mode mMode;
    uint8_t* mKey;
    uint8_t* mIV;
};