#include "CrustAllocator.hpp"

#include <cxxabi.h>
#include <dlfcn.h>
#include <execinfo.h>
#include <unistd.h>

#include <atomic>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <iostream>
#include <mutex>
#include <sstream>
#include <thread>
#include <vector>

#include "CrustInternal.hpp"
#include "CrustLogger.hpp"
#include "CrustQuarantine.hpp"
#include "CrustShadow.hpp"

static bool graceful_mode = []
{
    const char* mode = std::getenv("CRUST_GRACEFUL_MODE");
    return mode && std::strcmp(mode, "1") == 0;
}();

static thread_local bool in_secure_alloc = false;

namespace crust
{
    // demangle C++ symbol names.
    static std::string demangle_symbol(const char* mangled_name)
    {
        int status = 0;
        char* demangled = abi::__cxa_demangle(mangled_name, nullptr, nullptr, &status);
        std::string result = (status == 0 && demangled) ? demangled : mangled_name;
        free(demangled);
        return result;
    }

    // Utility: Print a stack trace when CRUST_DEBUG=1.
    static void print_stack_trace()
    {
        const char* CRUST_DEBUG = std::getenv("CRUST_DEBUG");
        if (CRUST_DEBUG && std::strcmp(CRUST_DEBUG, "1") == 0)
        {
            constexpr int max_frames = 32;
            void* frames[max_frames];
            int count = backtrace(frames, max_frames);
            std::ostringstream oss;
            oss << "Stack trace (" << count << " frames):\n";
            for (int i = 0; i < count; ++i)
            {
                Dl_info info;
                if (dladdr(frames[i], &info) && info.dli_sname)
                {
                    std::string demangled = demangle_symbol(info.dli_sname);
                    ptrdiff_t offset = static_cast<char*>(frames[i]) - static_cast<char*>(info.dli_saddr);
                    oss << "  " << i << ": " << info.dli_fname << " : " << demangled << " + " << offset << "\n";
                }
                else
                {
                    oss << "  " << i << ": " << frames[i] << "\n";
                }
            }
            std::string trace_str = oss.str();
            write(STDERR_FILENO, trace_str.c_str(), trace_str.size());
        }
    }

    // Centralized error handler: Logs error details, prints the stack trace and aborts.
    static void handle_critical_error(const std::string& error_msg, void* ptr = nullptr, shadow_record* rec = nullptr)
    {
        log_message("ERROR", "Critical error: {}", error_msg);
        if (ptr)
        {
            log_message("ERROR", "Affected pointer: {}", ptr);
        }
        if (rec)
        {
            log_message("ERROR", "Allocation backtrace:");
            for (int i = 0; i < rec->bt_size; ++i)
            {
                log_message("ERROR", "  Frame {}: {}", i, rec->backtrace[i]);
            }
        }
        print_stack_trace();
        if (graceful_mode)
        {
            log_message("ERROR", "Graceful mode enabled: dumping additional allocation context before aborting.");
            // ideally dump
        }
        abort();
    }

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

    // secure_malloc: Allocates memory with a header and redzones, and adds a shadow record.
    void* secure_malloc(std::size_t size)
    {
        if (in_secure_alloc)
            return get_real_malloc()(size);
        in_secure_alloc = true;

        void* bt[16];
        int bt_size = backtrace(bt, 16);
        int pool_type = (size <= SMALL_POOL_THRESHOLD) ? 0 : 1;
        size_t total_size = sizeof(header_t) + REDZONE_SIZE + size + REDZONE_SIZE;
        auto raw_ptr = reinterpret_cast<uint8_t*>(get_real_malloc()(total_size));
        if (!raw_ptr)
        {
            in_secure_alloc = false;
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
        in_secure_alloc = false;
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
        in_secure_alloc = true;

        uint8_t* user_ptr = reinterpret_cast<uint8_t*>(ptr);
        auto header = reinterpret_cast<header_t*>(user_ptr - REDZONE_SIZE - sizeof(header_t));

        if (header->canary != CANARY_VALUE)
        {
            handle_critical_error("Header corruption detected", ptr);
        }

        // check the redzones for overflow.
        bool redzone_error = false;
        uint8_t* redzone_front = reinterpret_cast<uint8_t*>(header) + sizeof(header_t);
        for (unsigned int i = 0; i < REDZONE_SIZE; i++)
        {
            if (redzone_front[i] != REDZONE_PATTERN)
            {
                log_message("ERROR", "Redzone front corrupted at {} (offset {})", static_cast<const void*>(redzone_front + i), i);
                redzone_error = true;
                break;
            }
        }
        uint8_t* redzone_back = user_ptr + header->size;
        for (unsigned int i = 0; i < REDZONE_SIZE; i++)
        {
            if (redzone_back[i] != REDZONE_PATTERN)
            {
                log_message("ERROR", "Redzone back corrupted at {} (offset {})", static_cast<const void*>(redzone_back + i), i);
                redzone_error = true;
                break;
            }
        }
        if (redzone_error)
        {
            handle_critical_error("Buffer overflow detected (redzone corruption)", ptr);
        }

        auto rec = find_shadow_record(ptr);
        if (!rec)
        {
            handle_critical_error("Invalid free: pointer was not allocated by Crust", ptr);
        }
        if (rec->is_freed.load())
        {
            handle_critical_error("Double free detected", ptr, rec);
        }

        check_shadow_record(ptr);

        std::memset(user_ptr, 0xDE, header->size);

        mark_shadow_record_freed(ptr);
        size_t total_size = sizeof(header_t) + REDZONE_SIZE + header->size + REDZONE_SIZE;
        add_to_quarantine(reinterpret_cast<void*>(header), total_size);
        flush_quarantine();
        log_message("INFO", "Freed {} bytes from {} (pool: {})", header->size, static_cast<const void*>(ptr), (header->pool_type == 0 ? "small" : "large"));
        in_secure_alloc = false;
    }

    // Iterates over all active allocations and verifies header and redzone integrity.
    void validate_all_allocations()
    {
        shadow_record* rec = get_shadow_head_ptr();
        while (rec)
        {
            if (!rec->is_freed.load())
            {
                uint8_t* user_ptr = reinterpret_cast<uint8_t*>(rec->user_ptr);
                header_t* header = reinterpret_cast<header_t*>(user_ptr - REDZONE_SIZE - sizeof(header_t));
                if (header->canary != CANARY_VALUE)
                {
                    log_message("ERROR", "Global validation: header corruption detected for pointer {}", rec->user_ptr);
                }
                uint8_t* redzone_front = reinterpret_cast<uint8_t*>(header) + sizeof(header_t);
                for (unsigned int i = 0; i < REDZONE_SIZE; i++)
                {
                    if (redzone_front[i] != REDZONE_PATTERN)
                    {
                        log_message("ERROR", "Global validation: redzone front corruption at pointer {} (offset {})", rec->user_ptr, i);
                        break;
                    }
                }
                uint8_t* redzone_back = user_ptr + header->size;
                for (unsigned int i = 0; i < REDZONE_SIZE; i++)
                {
                    if (redzone_back[i] != REDZONE_PATTERN)
                    {
                        log_message("ERROR", "Global validation: redzone back corruption at pointer {} (offset {})", rec->user_ptr, i);
                        break;
                    }
                }
            }
            rec = rec->next;
        }
        log_message("INFO", "Global allocation validation completed");
    }

    static void signal_handler(int signum)
    {
        log_message("INFO", "Received signal {}: Starting global allocation validation", signum);
        validate_all_allocations();
    }

    __attribute__((constructor)) static void init_crust_signal_handler()
    {
        std::signal(SIGUSR1, signal_handler);
        log_message("INFO", "Crust signal handler for SIGUSR1 registered");
    }

    void dump_leaks()
    {
        shadow_record* rec = get_shadow_head_ptr();
        int leak_count = 0;
        while (rec)
        {
            if (!rec->is_freed.load())
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
void operator delete(void* ptr, std::size_t) noexcept
{
    crust::secure_free(ptr);
}
void operator delete[](void* ptr, std::size_t) noexcept
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
