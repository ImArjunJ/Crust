#pragma once
#include <mutex>

namespace crust
{
    inline std::mutex crust_mutex;

    inline constexpr unsigned int QUARANTINE_DELAY = 2;       // seconds
    inline constexpr unsigned int REDZONE_SIZE = 16;          // bytes for redzones
    inline constexpr unsigned int SMALL_POOL_THRESHOLD = 128; // threshold for small pool
    inline constexpr unsigned char REDZONE_PATTERN = 0xAB;
    inline constexpr unsigned int CANARY_VALUE = 0xDEADBEEF;
} // namespace crust
