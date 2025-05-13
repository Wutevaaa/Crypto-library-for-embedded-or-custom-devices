#pragma once
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <array>
#include <queue>

#include <AES_base.hpp>
#define byte uint8_t

namespace hls {
    template<typename T>
    class stream {
    public:
        std::queue<T> q;

        void write(const T &val) {
            q.push(val);
        }

        T read() {
            T val = q.front();
            q.pop();
            return val;
        }

        bool empty() const {
            return q.empty();
        }
    };
};


template<int W>
class ap_uint {
private:
    uint32_t val;
public:
    ap_uint(uint32_t v = 0) : val(v) {}

    operator uint32_t() const { return val; }

    ap_uint &operator=(uint32_t v) {
        val = v;
        return *this;
    }

    ap_uint operator^(const ap_uint &other) const { return val ^ other.val; }

    ap_uint &operator^=(const ap_uint &other) {
        val ^= other.val;
        return *this;
    }

    ap_uint operator<<(int shift) const { return val << shift; }

    ap_uint operator>>(int shift) const { return val >> shift; }

    class range_proxy {
    private:
        ap_uint &parent;
        int high, low;
    public:
        range_proxy(ap_uint &p, int h, int l) : parent(p), high(h), low(l) {}

        range_proxy &operator=(uint32_t value) {
            uint32_t mask = ((1u << (high - low + 1)) - 1) << low;
            parent.val = (parent.val & ~mask) | ((value << low) & mask);
            return *this;
        }

        range_proxy &operator^=(uint32_t value) {
            uint32_t current = (parent.val >> low) & ((1u << (high - low + 1)) - 1);
            current ^= value;
            *this = current;
            return *this;
        }

        operator uint32_t() const {
            return (parent.val >> low) & ((1u << (high - low + 1)) - 1);
        }
    };

    range_proxy range(int high, int low) {
        return range_proxy(*this, high, low);
    }

    range_proxy range(int high, int low) const {
        // Cast away const for read-only use
        return range_proxy(*const_cast<ap_uint*>(this), high, low);
    }
};

#define NOT_RUNNING_VITIS
class AES_hls : public AES_base{
private:
#include <aes_hls_noopt.cpp>
    void load_key(const uint8_t* input_key, hlskey_t& key) {
        for (int i = 0; i < 32; ++i) {
            key[i] = static_cast<byte>(input_key[i]);
        }
    }

    void load_iv(const uint8_t* input_iv, block_t& iv) {
        for (int i = 0; i < 16; ++i) {
            iv[i] = static_cast<byte>(input_iv[i]);
        }
    }

    hlskey_t mkey;
    block_t miv;

public:
    AES_hls() {setName("AES-hls");}

    void init(const uint8_t* key, crypto_mode mode, const uint8_t* iv) override {
        AES_base::init(key, mode, iv);
        switch(mode) {
            case AES_base::MODE_CTR_INPLACE:
            case AES_base::MODE_CTR_STANDARD:
                load_iv(iv, miv);

            case AES_base::MODE_ECB_INPLACE:
            case AES_base::MODE_ECB_STANDARD:
                load_key(key, mkey);
                break;
        }
    }

    virtual void encrypt(uint8_t* in, uint8_t* out, size_t size) override {
        switch(getCryptoMode()) {
            case AES_base::MODE_ECB_STANDARD: {
                const int num_blocks = size / AES_BLOCK_SIZE_BYTES;
                hls::stream<axis_t> in_stream, out_stream;

                for (int i = 0; i < size; ++i) {
                    axis_t t;
                    t.data = static_cast<byte>(in[i]);
                    t.last = (i == size - 1);
                    in_stream.write(t);
                }
                aes256_ecb_encrypt_stream(in_stream, out_stream, mkey, num_blocks);
                for (int i = 0; i < size; ++i) {
                    axis_t t = out_stream.read();
                    out[i] = static_cast<int8_t>(t.data);
                }
                break;
            }
            case AES_base::MODE_CTR_STANDARD: {
                const int num_blocks = size / AES_BLOCK_SIZE_BYTES;
                hls::stream<axis_t> in_stream, out_stream;

                for (int i = 0; i < size; ++i) {
                    axis_t t;
                    t.data = static_cast<byte>(in[i]);
                    t.last = (i == size - 1);
                    in_stream.write(t);
                }
                aes256_ctr_encrypt_stream(in_stream, out_stream, mkey, miv, num_blocks);
                for (int i = 0; i < size; ++i) {
                    axis_t t = out_stream.read();
                    out[i] = static_cast<int8_t>(t.data);
                }

                break;
            }
            default:
                throw "Not implemented";
        }
    }

    virtual void decrypt(uint8_t* in, uint8_t* out, size_t size) override {
        switch(getCryptoMode()) {
            case AES_base::MODE_ECB_STANDARD: {
                const int num_blocks = size / AES_BLOCK_SIZE_BYTES;
                hls::stream<axis_t> in_stream, out_stream;

                for (int i = 0; i < size; ++i) {
                    axis_t t;
                    t.data = static_cast<byte>(in[i]);
                    t.last = (i == size - 1);
                    in_stream.write(t);
                }
                aes256_ecb_decrypt_stream(in_stream, out_stream, mkey, num_blocks);
                for (int i = 0; i < size; ++i) {
                    axis_t t = out_stream.read();
                    out[i] = static_cast<int8_t>(t.data);
                }
                break;
            }
            case AES_base::MODE_CTR_STANDARD: {
                // not a mistake, encrypt == decrypt in CTR mode
                const int num_blocks = size / AES_BLOCK_SIZE_BYTES;
                hls::stream<axis_t> in_stream, out_stream;

                for (int i = 0; i < size; ++i) {
                    axis_t t;
                    t.data = static_cast<byte>(in[i]);
                    t.last = (i == size - 1);
                    in_stream.write(t);
                }
                aes256_ctr_encrypt_stream(in_stream, out_stream, mkey, miv, num_blocks);
                for (int i = 0; i < size; ++i) {
                    axis_t t = out_stream.read();
                    out[i] = static_cast<int8_t>(t.data);
                }
                break;
            }
            default:
                throw "Not implemented";
        }
    }
};