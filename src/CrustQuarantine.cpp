#include "CrustQuarantine.hpp"

#include <dlfcn.h>

#include <cstring>
#include <ctime>
#include <mutex>
#include <vector>

#include "CrustCommon.hpp"
#include "CrustInternal.hpp"
#include "CrustLogger.hpp"

namespace crust
{

    static quarantine_node* quarantine_head = nullptr;

    static void call_real_free(void* ptr)
    {
        using free_t = void (*)(void*);
        static free_t real_free = reinterpret_cast<free_t>(dlsym(RTLD_NEXT, "free"));
        if (real_free)
            real_free(ptr);
    }

    void add_to_quarantine(void* raw_ptr, size_t total_size)
    {
        std::lock_guard lock(crust_mutex);
        auto node = new quarantine_node;
        node->raw_ptr = raw_ptr;
        node->total_size = total_size;
        node->timestamp = std::time(nullptr);
        node->next = quarantine_head;
        quarantine_head = node;
        log_message("INFO", "Allocation added to quarantine");
    }

    void flush_quarantine()
    {
        std::vector<quarantine_node*> nodes_to_free;
        {
            std::lock_guard lock(crust_mutex);
            time_t now = std::time(nullptr);
            quarantine_node** cur = &quarantine_head;
            while (*cur)
            {
                quarantine_node* node = *cur;
                if (now - node->timestamp >= QUARANTINE_DELAY)
                {
                    nodes_to_free.push_back(node);
                    *cur = node->next;
                }
                else
                {
                    cur = &node->next;
                }
            }
        }
        // For each node, check for use-after-free by verifying poison.
        for (auto node : nodes_to_free)
        {
            // Compute user_ptr: it's at (header + sizeof(header_t) + REDZONE_SIZE)
            auto header = reinterpret_cast<uint8_t*>(node->raw_ptr);
            uint8_t* user_ptr = header + sizeof(crust::header_t) + REDZONE_SIZE;
            size_t user_size = node->total_size - (sizeof(crust::header_t) + 2 * REDZONE_SIZE);
            bool poison_intact = true;
            for (size_t i = 0; i < user_size; i++)
            {
                if (user_ptr[i] != 0xDE)
                { // Poison value used in secure_free.
                    poison_intact = false;
                    break;
                }
            }
            if (!poison_intact)
            {
                log_message("ERROR", "Use-after-free detected in quarantined block at {}", static_cast<const void*>(user_ptr));
            }
            call_real_free(node->raw_ptr);
            call_real_free(node);
            log_message("INFO", "Flushed quarantine allocation");
        }
    }

} // namespace crust
