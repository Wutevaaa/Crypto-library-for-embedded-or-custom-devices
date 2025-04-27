#include <iostream>
#include <Utils.hpp>
#include <aes.hpp>

int main() {

    uint64_t millis_encryption = 0;
    uint64_t millis_decryption = 0;
    uint64_t speedtestsize = 1024*1024*1024;

    //AES_base* codec = new AES_tiny();
    //AES_base* codec = new AES_cortexm();
    //AES_base* codec = new AES_ni();
    //AES_base* codec = new AES_ni_sse();
    AES_base* codecs[] = {new AES_tiny(), new AES_small(), new AES_ni(), new AES_ni_sse(), new AES_ni_avx2(), new AES_ni_omp()};
    for (auto codec : codecs) {
        codec->test(millis_encryption, millis_decryption, speedtestsize);
        std::cout << codec->getName() << " CTR encryption throughput: " << (speedtestsize / millis_encryption) / 1000000. << " GB/s"
                  << std::endl;
        std::cout << codec->getName() << " CTR decryption throughput: " << (speedtestsize / millis_decryption) / 1000000. << " GB/s"
                  << std::endl;
        std::cout << std::endl;
    }

    for (auto codec : codecs)
        delete(codec);

    return 0;
}
