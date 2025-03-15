#pragma once
#include <cstddef>
#include <ctime>

namespace crust
{

    struct quarantine_node
    {
        void* raw_ptr;
        size_t total_size;
        time_t timestamp;
        quarantine_node* next;
    };

    void add_to_quarantine(void* raw_ptr, size_t total_size);
    void flush_quarantine();

} // namespace crust
