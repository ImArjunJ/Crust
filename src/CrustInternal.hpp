#ifndef CRUST_INTERNAL_HPP
#define CRUST_INTERNAL_HPP

#include "CrustCommon.hpp"

namespace crust
{

    struct header_t
    {
        void* raw_ptr;   // Original pointer from real malloc.
        uint32_t canary; // Canary value.
        size_t size;     // Requested allocation size.
        int pool_type;   // 0 = small, 1 = large.
    };

} // namespace crust

#endif // CRUST_INTERNAL_HPP
