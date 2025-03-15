#ifndef CRUST_SHADOW_HPP
#define CRUST_SHADOW_HPP

#include <cstddef>

namespace crust
{

    struct shadow_record
    {
        void* user_ptr;      // Pointer returned to the user.
        size_t size;         // Requested allocation size.
        int pool_type;       // 0 = small, 1 = large.
        int is_freed;        // 0 = allocated, 1 = freed.
        void* backtrace[16]; // Captured backtrace pointers.
        int bt_size;         // Number of frames captured.
        shadow_record* next;
    };

    void add_shadow_record(void* user_ptr, size_t size, int pool_type, void** bt, int bt_size);
    void mark_shadow_record_freed(void* user_ptr);
    void check_shadow_record(void* user_ptr);
    shadow_record* get_shadow_head_ptr();

} // namespace crust

#endif // CRUST_SHADOW_HPP
