#pragma once
#include <cstdint>

namespace crust
{

    struct header_t
    {
        void* raw_ptr;   // Original pointer from real malloc.
        uint32_t canary; // Canary value.
        size_t size;     // Requested allocation size.
        int pool_type;   // 0 = small, 1 = large.
        uint8_t tag;     // Random tag for pointer provenance.
    };

} // namespace crust
