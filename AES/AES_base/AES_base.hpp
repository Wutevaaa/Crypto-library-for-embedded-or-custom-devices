#pragma once

class AES_base {
public:
    virtual void init(uint8_t* key, uint8_t* iv) = 0;
    virtual void encrypt(uint8_t* in, size_t size) = 0;

    virtual int accuracytest(uint64_t& millis) = 0;
    virtual void speedtest(uint64_t& millis) = 0;
};