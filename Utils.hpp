#pragma once
#include <cstdint>
#include <chrono>

class Utils {
public:
    static uint64_t getMillis() {
        auto duration = std::chrono::system_clock::now().time_since_epoch();
        auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
        return millis;
    }
};