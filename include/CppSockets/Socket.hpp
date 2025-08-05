/*
** Project CppSockets, 2022
**
** Author Francois Michaut
**
** Started on  Sat Jan 15 01:17:42 2022 Francois Michaut
** Last update Tue Aug  5 00:00:48 2025 Francois Michaut
**
** Socket.hpp : Portable C++ socket class
*/

#pragma once

#include "CppSockets/OSDetection.hpp"
#include "CppSockets/SocketInit.hpp"

// TODO: move the RawSocketType in CppSockets namespace
#ifdef OS_WINDOWS
  #define NOMINMAX
  #include <winsock2.h>
  using RawSocketType=SOCKET;
  using socklen_t=int;
  using SockOptType=char;
#else
  #include <sys/socket.h>
  using RawSocketType=int;
  using SockOptType=void;
#endif

#include <memory>

#include "CppSockets/Address.hpp"

namespace CppSockets {
    class Socket : SocketInit {
        public:
            Socket();
            Socket(int domain, int type, int protocol);
            Socket(RawSocketType fd, bool connected);
            ~Socket();

            // TODO Maybe enable copy with dup(2) ?
            Socket(const Socket &other) = delete;
            Socket(Socket &&other) noexcept;
            auto operator=(const Socket &other) -> Socket & = delete;
            auto operator=(Socket &&other) noexcept -> Socket &;

            auto read(std::size_t len = -1) -> std::string;
            auto read(char *buff, std::size_t size) -> std::size_t;
            auto write(const std::string &buff) -> std::size_t;
            auto write(const char *buff, std::size_t len) -> std::size_t;

            auto set_reuseaddr(bool value) -> int;
            auto getsockopt(int level, int optname, SockOptType *optval, socklen_t *optlen) -> int;
            auto setsockopt(int level, int optname, const SockOptType *optval, socklen_t optlen) -> int;

            void close();
            auto connect(const IEndpoint &endpoint) -> int;
            auto connect(const std::string &addr, uint16_t port) -> int;

            auto bind(const IEndpoint &endpoint) -> int;
            auto bind(const std::string &addr, uint16_t port) -> int;
            auto listen(int backlog) -> int;
            auto accept(void *addr_out = nullptr) -> std::unique_ptr<Socket>;

            void set_blocking(bool val);

            [[nodiscard]]
            auto get_fd() const -> RawSocketType { return m_sockfd; }
            [[nodiscard]]
            auto get_type() const -> int { return m_type; }
            [[nodiscard]]
            auto get_domain() const -> int { return m_domain; }
            [[nodiscard]]
            auto get_protocol() const -> int { return m_protocol; }
            // TODO: Allow to get Endpoint

            [[nodiscard]]
            auto connected() const -> bool { return m_is_connected; }

            static auto get_errno() -> int;
            static auto strerror(int err) -> char *;
            static auto strerror() -> char *;

        protected:
            static auto getsockopt(int fd, int level, int optname, SockOptType *optval, socklen_t *optlen) -> int;
            auto bind(std::uint32_t addr, uint16_t port) -> int;

            void set_connected(bool status) { m_is_connected = status; };

        private:
            int m_domain = 0;
            int m_type = 0;
            int m_protocol = 0;
            RawSocketType m_sockfd;
            bool m_is_connected = false;
    };
}
