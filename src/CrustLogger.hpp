#pragma once
#define CRUST_DEBUG

#include <unistd.h>

#include <cstring>
#include <ctime>
#include <format>
#include <string>

#include "CrustCommon.hpp"

namespace crust
{

    // The format string must be a literal.
    template <typename... Args>
    void log_message(const char* level, std::format_string<Args...> fmt, Args&&... args)
    {
        char time_buf[64];
        time_t now = time(nullptr);
        struct tm tm_info;
        localtime_r(&now, &tm_info);
        strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", &tm_info);

        const char* color = (std::strcmp(level, "INFO") == 0)    ? "\033[1;32m"
                            : (std::strcmp(level, "WARN") == 0)  ? "\033[1;33m"
                            : (std::strcmp(level, "ERROR") == 0) ? "\033[1;31m"
                                                                 : "\033[1;34m";

        std::string user_msg = std::format(fmt, std::forward<Args>(args)...);

        std::string log_str = std::format("\033[1;36m[Crust]\033[0m \033[1;35m{}\033[0m {}[{}]\033[0m {}", time_buf, color, level, user_msg);
        if (log_str.back() != '\n')
            log_str.push_back('\n');

#ifdef CRUST_DEBUG
        write(STDERR_FILENO, log_str.c_str(), log_str.size());
#else
        if (std::strcmp(level, "ERROR") == 0 || std::strcmp(level, "WARN") == 0)
            write(STDERR_FILENO, log_str.c_str(), log_str.size());
#endif
    }

} // namespace crust
