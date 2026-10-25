/*
** Project LibCppSockets, 2026
**
** Author Francois Michaut
**
** Started on  Mon Oct 26 22:28:56 2026 Francois Michaut
** Last update Mon Oct 26 23:02:45 2026 Francois Michaut
**
** ErrorUtils.cpp : Portable system error utilities implementation
*/

#include "CppSockets/ErrorUtils.hpp"
#include "CppSockets/OSDetection.hpp"

#ifdef OS_WINDOWS
  #include <winsock2.h>
#else
  #include <cerrno>
#endif

#include <system_error>

namespace {
    class socket_error_category final : public std::error_category {
        public:
            auto name() const noexcept -> const char * override {
#ifdef OS_WINDOWS
                return "Winsock";
#else
                return "errno";
#endif
            }

            auto message(int err) const -> std::string override {
#ifdef OS_WINDOWS
                char *msg = nullptr;

                FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM
                               | FORMAT_MESSAGE_IGNORE_INSERTS,
                               nullptr, err, 0, (LPSTR)&msg, 0, nullptr);
                std::string result(msg ? msg : "Unknown error");
                LocalFree(msg);
                return result;
#else
                return std::system_category().message(err);
#endif
            }
    };

    auto socket_category() -> const std::error_category & {
        static const socket_error_category instance{};
        return instance;
    }
}

namespace CppSockets {
    auto strerror(int err) -> std::string {
        return std::error_code(err, socket_category()).message();
    }

    auto get_errno() -> int {
#ifdef OS_WINDOWS
        return WSAGetLastError();
#else
        return errno;
#endif
    }

    auto strerror() -> std::string {
        return strerror(get_errno());
    }
}
