#pragma once
#include <cstddef>

namespace crust
{
    void* secure_malloc(std::size_t size);
    void secure_free(void* ptr);
    void dump_leaks();
} // namespace crust
