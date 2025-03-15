#include "CrustAllocator.hpp"

#include <dlfcn.h>
#include <execinfo.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>

#include "CrustCommon.hpp"
#include "CrustInternal.hpp"
#include "CrustLogger.hpp"
#include "CrustQuarantine.hpp"
#include "CrustShadow.hpp"

static thread_local int in_secure_alloc = 0;

namespace crust
{

    using malloc_t = void* (*) (size_t);
    using free_t = void (*)(void*);

    static malloc_t get_real_malloc()
    {
        static malloc_t ptr = nullptr;
        if (!ptr)
        {
            ptr = reinterpret_cast<malloc_t>(dlsym(RTLD_NEXT, "malloc"));
            if (!ptr)
            {
                std::fprintf(stderr, "Error in dlsym for malloc: %s\n", strerror(errno));
                std::exit(1);
            }
        }
        return ptr;
    }

    static free_t get_real_free()
    {
        static free_t ptr = nullptr;
        if (!ptr)
        {
            ptr = reinterpret_cast<free_t>(dlsym(RTLD_NEXT, "free"));
            if (!ptr)
            {
                std::fprintf(stderr, "Error in dlsym for free: %s\n", strerror(errno));
                std::exit(1);
            }
        }
        return ptr;
    }

    void* secure_malloc(std::size_t size)
    {
        if (in_secure_alloc)
            return get_real_malloc()(size);
        in_secure_alloc = 1;

        void* bt[16];
        int bt_size = backtrace(bt, 16);
        int pool_type = (size <= SMALL_POOL_THRESHOLD) ? 0 : 1;
        size_t total_size = sizeof(header_t) + REDZONE_SIZE + size + REDZONE_SIZE;
        auto raw_ptr = reinterpret_cast<uint8_t*>(get_real_malloc()(total_size));
        if (!raw_ptr)
        {
            in_secure_alloc = 0;
            return nullptr;
        }
        auto header = reinterpret_cast<header_t*>(raw_ptr);
        header->raw_ptr = raw_ptr;
        header->canary = CANARY_VALUE;
        header->size = size;
        header->pool_type = pool_type;

        uint8_t* redzone_front = raw_ptr + sizeof(header_t);
        std::memset(redzone_front, REDZONE_PATTERN, REDZONE_SIZE);
        uint8_t* user_ptr = redzone_front + REDZONE_SIZE;
        uint8_t* redzone_back = user_ptr + size;
        std::memset(redzone_back, REDZONE_PATTERN, REDZONE_SIZE);

        log_message("INFO", "Allocated {} bytes at {} (pool: {})", size, static_cast<const void*>(user_ptr), (pool_type == 0 ? "small" : "large"));
        add_shadow_record(user_ptr, size, pool_type, bt, bt_size);
        in_secure_alloc = 0;
        return user_ptr;
    }

    void secure_free(void* ptr)
    {
        if (!ptr)
            return;
        if (in_secure_alloc)
        {
            get_real_free()(ptr);
            return;
        }
        in_secure_alloc = 1;

        check_shadow_record(ptr);

        uint8_t* user_ptr = reinterpret_cast<uint8_t*>(ptr);
        auto header = reinterpret_cast<header_t*>(user_ptr - REDZONE_SIZE - sizeof(header_t));

        if (header->canary != CANARY_VALUE)
        {
            log_message("ERROR", "Header corruption detected at {}", static_cast<const void*>(ptr));
            mark_shadow_record_freed(ptr);
            in_secure_alloc = 0;
            return;
        }
        size_t size = header->size;
        int pool_type = header->pool_type;

        uint8_t* redzone_front = reinterpret_cast<uint8_t*>(header) + sizeof(header_t);
        for (unsigned int i = 0; i < REDZONE_SIZE; i++)
        {
            if (redzone_front[i] != REDZONE_PATTERN)
            {
                log_message("ERROR", "Redzone front corrupted at {} (offset {})", static_cast<const void*>(redzone_front + i), i);
                break;
            }
        }
        uint8_t* redzone_back = user_ptr + size;
        for (unsigned int i = 0; i < REDZONE_SIZE; i++)
        {
            if (redzone_back[i] != REDZONE_PATTERN)
            {
                log_message("ERROR", "Redzone back corrupted at {} (offset {})", static_cast<const void*>(redzone_back + i), i);
                break;
            }
        }

        // Poison the user region with 0xDE to help detect UAF errors.
        std::memset(user_ptr, 0xDE, size);

        // Mark the allocation as freed so it is not reported as a leak.
        mark_shadow_record_freed(ptr);

        size_t total_size = sizeof(header_t) + REDZONE_SIZE + size + REDZONE_SIZE;
        add_to_quarantine(reinterpret_cast<void*>(header), total_size);
        flush_quarantine();

        log_message("INFO", "Freed {} bytes from {} (pool: {})", size, static_cast<const void*>(ptr), (pool_type == 0 ? "small" : "large"));
        in_secure_alloc = 0;
    }

    void dump_leaks()
    {
        auto rec = get_shadow_head_ptr(); // Already locks shadow_mutex internally.
        int leak_count = 0;
        while (rec)
        {
            if (rec->is_freed == 0)
            {
                log_message("WARN", "Memory leak detected: pointer={}, size={}", rec->user_ptr, rec->size);
                leak_count++;
            }
            rec = rec->next;
        }
        if (leak_count > 0)
            log_message("WARN", "Crust Leak Report: {} leaks detected", leak_count);
        else
            log_message("INFO", "Crust Leak Report: No leaks detected");
    }

    struct LeakReporter
    {
        LeakReporter()
        {
            std::atexit(dump_leaks);
        }
    };
    static LeakReporter leakReporter;

} // namespace crust

void* operator new(std::size_t size) noexcept(false)
{
    if (void* ptr = crust::secure_malloc(size))
        return ptr;
    throw std::bad_alloc();
}
void operator delete(void* ptr) noexcept
{
    crust::secure_free(ptr);
}
void* operator new[](std::size_t size) noexcept(false)
{
    if (void* ptr = crust::secure_malloc(size))
        return ptr;
    throw std::bad_alloc();
}
void operator delete[](void* ptr) noexcept
{
    crust::secure_free(ptr);
}

extern "C"
{
    void* malloc(size_t size)
    {
        return crust::secure_malloc(size);
    }
    void free(void* ptr)
    {
        crust::secure_free(ptr);
    }
}
