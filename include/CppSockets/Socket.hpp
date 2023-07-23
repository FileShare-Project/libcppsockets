/*
** Project CppSockets, 2022
**
** Author Francois Michaut
**
** Started on  Sat Jan 15 01:17:42 2022 Francois Michaut
** Last update Sat Jul 22 19:43:35 2023 Francois Michaut
**
** Socket.hpp : Portable C++ socket class
*/

#pragma once

#include "CppSockets/OSDetection.hpp"

// TODO: move the RawSocketType in CppSockets namespace
#ifdef OS_WINDOWS
  #define NOMINMAX
  #include <winsock2.h>
  using RawSocketType=SOCKET;
  using socklen_t=int;
#else
  #include <sys/socket.h>
  using RawSocketType=int;
#endif

#include <memory>

#include "CppSockets/Address.hpp"

namespace CppSockets {
    static void init(bool init_ssl = true, bool init_wsa = true);
    static void deinit(bool deinit_ssl = true, bool deinit_wsa = true);

    class Socket {
        public:
            Socket();
            Socket(int domain, int type, int protocol);
            Socket(RawSocketType fd, bool connected);
            ~Socket();

            // TODO Maybe enable copy with dup(2) ?
            Socket(const Socket &other) = delete;
            Socket(Socket &&other) noexcept;
            Socket &operator=(const Socket &other) = delete;
            Socket &operator=(Socket &&other) noexcept;

            std::string read(std::size_t len = -1);
            std::size_t read(char *buff, std::size_t size);
            std::size_t write(const std::string &buff);
            std::size_t write(const char *buff, std::size_t len);

            int set_reuseaddr(bool value);
            int getsockopt(int level, int optname, void *optval, socklen_t *optlen);
            int setsockopt(int level, int optname, const void *optval, socklen_t optlen);

            void close();
            int connect(const IEndpoint &endpoint);
            int connect(const std::string &addr, uint16_t port);

            int bind(const IEndpoint &endpoint);
            int bind(const std::string &addr, uint16_t port);
            int listen(int backlog);
            std::shared_ptr<Socket> accept(void *addr_out = nullptr);

            void set_blocking(bool val);

            [[nodiscard]]
            RawSocketType get_fd() const; // TODO check if windows SOCKET can be
                                          // converted to int
            [[nodiscard]]
            int get_type() const;
            [[nodiscard]]
            int get_domain() const;
            [[nodiscard]]
            int get_protocol() const;

            [[nodiscard]]
            bool connected() const;

        public:
            static int get_errno();
            static char *strerror(int err);
            static char *strerror();

        protected:
            static int getsockopt(int fd, int level, int optname, void *optval, socklen_t *optlen);
            int bind(std::uint32_t addr, uint16_t port);

            int domain = 0;
            int type = 0;
            int protocol = 0;
            RawSocketType sockfd;
            bool is_connected = false;
    };
}
