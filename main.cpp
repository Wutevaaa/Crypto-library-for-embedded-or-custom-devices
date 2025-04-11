#include <iostream>
#include <aes.hpp>
#include <Utils.hpp>

int main() {

    uint64_t millis = 0;
    AEStiny::speedtest(millis);
    std::cout << millis << " ms" << std::endl;

    return 0;
}
