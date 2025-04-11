#include <iostream>
#include <Utils.hpp>
#include <aes.hpp>

int main() {

    uint64_t millis = 0;

    AES_base* codec = new AES_tiny();
    //AES_base* codec = new AES_cortexm();

    codec->speedtest(millis);
    std::cout << millis << " ms" << std::endl;

    return 0;
}
