/*
** Project LibCppSockets, 2022
**
** Author Francois Michaut
**
** Started on  Sat Jan 15 01:17:42 2022 Francois Michaut
** Last update Mon Oct 26 20:22:18 2026 Francois Michaut
**
** Socket.hpp : Portable C++ socket class
*/

#pragma once

#include "CppSockets/Address.hpp"
#include "CppSockets/OSDetection.hpp"
#include "CppSockets/PollEvent.hpp"

// TODO: move the RawSocketType in CppSockets namespace
#ifdef OS_WINDOWS
  #include <winsock2.h>
  using RawSocketType=SOCKET;
  using socklen_t=int;
  using SockOptType=char;
  using PollfdType=WSAPOLLFD;
#else
  #include <sys/socket.h>
  using RawSocketType=int;
  using SockOptType=void;
  using PollfdType=struct pollfd;
#endif

#include <cstdint>
#include <memory>

#include "CppSockets/internal/SocketInit.hpp"

namespace CppSockets {
    class Socket : SocketInit {
        public:
            Socket();
            Socket(int domain, int type, int protocol);
            Socket(RawSocketType fd, bool connected);
            virtual ~Socket();

            // TODO Maybe enable copy with dup(2) ?
            Socket(const Socket &other) = delete;
            Socket(Socket &&other) noexcept;
            auto operator=(const Socket &other) -> Socket & = delete;
            auto operator=(Socket &&other) noexcept -> Socket &;

            virtual void close();

            // TODO: Add support for writev/WSASend and sendfile/WSATransmitPackets

            // read() with no lenght blocks once then returns all currently available data
            auto read(std::size_t len = -1) -> std::string;
            virtual auto read(char *buff, std::size_t size) -> std::size_t;
            auto write(std::string_view buff) -> std::size_t { return this->write(buff.data(), buff.size()); };
            virtual auto write(const char *buff, std::size_t len) -> std::size_t;

            auto set_reuseaddr(bool value) -> int;
            auto getsockopt(int level, int optname, SockOptType *optval, socklen_t *optlen) -> int;
            auto setsockopt(int level, int optname, const SockOptType *optval, socklen_t optlen) -> int;

            virtual auto connect(const IEndpoint &endpoint) -> int;
            virtual auto connect(const std::string &addr, uint16_t port) -> int;

            auto bind(const IEndpoint &endpoint) -> int;
            auto bind(const std::string &addr, uint16_t port) -> int;
            auto listen(int backlog) -> int;

            auto accept() -> std::unique_ptr<Socket>;
            auto accept(sockaddr_storage &addr) -> std::unique_ptr<Socket>;

            [[nodiscard]] auto poll(PollEvent events, int timeout_ms = 0) const -> PollEvent;

            void set_blocking(bool val);

            [[nodiscard]] auto get_fd() const -> RawSocketType { return m_sockfd; }
            [[nodiscard]] auto get_type() const -> int { return m_type; }
            [[nodiscard]] auto get_domain() const -> int { return m_domain; }
            [[nodiscard]] auto get_protocol() const -> int { return m_protocol; }
            // TODO: Allow to get Endpoint

            [[nodiscard]] auto connected() const -> bool { return m_is_connected; }

        protected:
            static void throw_errno_error(std::string message);
            static void throw_errno_error(std::string message, int err);

            static auto getsockopt(int fd, int level, int optname, SockOptType *optval, socklen_t *optlen) -> int;
            static auto getsockopt(int fd, int level, int optname, SockOptType *optval, socklen_t optlen) -> int { return Socket::getsockopt(fd, level, optname, optval, &optlen); }

            auto bind(std::uint32_t addr, uint16_t port) -> int;

            void set_connected(bool status) { m_is_connected = status; };

            void create_socket();

            [[nodiscard]] virtual auto has_more_data() const -> bool;
            virtual auto acceptImpl(sockaddr_storage *addr_out) -> Socket *;
        private:
            int m_domain = 0;
            int m_type = 0;
            int m_protocol = 0;
            RawSocketType m_sockfd;
            bool m_is_connected = false;
    };
}
