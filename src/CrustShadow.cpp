#include "CrustShadow.hpp"

#include <atomic>
#include <cstring>
#include <mutex>

#include "CrustLogger.hpp"

namespace crust
{
    static std::mutex shadow_mutex;
    static shadow_record* shadow_head = nullptr;

    void add_shadow_record(void* user_ptr, size_t size, int pool_type, void** bt, int bt_size)
    {
        std::lock_guard<std::mutex> lock(shadow_mutex);
        auto rec = new shadow_record;
        rec->user_ptr = user_ptr;
        rec->size = size;
        rec->pool_type = pool_type;
        rec->is_freed.store(false);
        rec->bt_size = bt_size;
        std::memcpy(rec->backtrace, bt, bt_size * sizeof(void*));
        rec->next = shadow_head;
        shadow_head = rec;
    }

    shadow_record* find_shadow_record(void* user_ptr)
    {
        std::lock_guard<std::mutex> lock(shadow_mutex);
        shadow_record* rec = shadow_head;
        while (rec)
        {
            if (rec->user_ptr == user_ptr)
                return rec;
            rec = rec->next;
        }
        return nullptr;
    }

    void mark_shadow_record_freed(void* user_ptr)
    {
        std::lock_guard<std::mutex> lock(shadow_mutex);
        shadow_record* rec = shadow_head;
        while (rec)
        {
            if (rec->user_ptr == user_ptr)
            {
                rec->is_freed.store(true);
                return;
            }
            rec = rec->next;
        }
        log_message("WARN", "Warning: freeing unknown pointer {}", static_cast<const void*>(user_ptr));
    }

    void check_shadow_record(void* user_ptr)
    {
        std::lock_guard<std::mutex> lock(shadow_mutex);
        shadow_record* rec = shadow_head;
        while (rec)
        {
            if (rec->user_ptr == user_ptr)
            {
                if (rec->is_freed.load())
                    log_message("ERROR", "Use-after-free detected at {}", static_cast<const void*>(user_ptr));
                return;
            }
            rec = rec->next;
        }
    }

    shadow_record* get_shadow_head_ptr()
    {
        std::lock_guard<std::mutex> lock(shadow_mutex);
        return shadow_head;
    }
} // namespace crust
