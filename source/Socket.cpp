/*
** Project LibCppSockets, 2022
**
** Author Francois Michaut
**
** Started on  Sat Jan 15 01:27:40 2022 Francois Michaut
** Last update Mon Oct 26 18:30:50 2026 Francois Michaut
**
** Socket.cpp : Protable C++ socket class implementation
*/

#include "CppSockets/IPv4.hpp"
#include "CppSockets/ErrorUtils.hpp"
#include "CppSockets/OSDetection.hpp"
#include "CppSockets/Socket.hpp"
#include "CppSockets/SocketInternals.hpp"

#ifdef OS_WINDOWS
  #include <io.h>
  #include <ws2tcpip.h>

  // Match linux defines
  #define SHUT_RDWR SD_BOTH
#else
  #include <arpa/inet.h>
  #include <fcntl.h>
  #include <netinet/in.h>
  #include <poll.h>
  #include <unistd.h>

  // To match windows's constants
  static constexpr int INVALID_SOCKET = -1;
  static constexpr int SOCKET_ERROR = -1;
#endif

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <iostream>
#include <stdexcept>

// TODO add exceptions on error retunrs
// TODO throw custom exceptions on invalid status (eg: socket already connected)
namespace CppSockets {
    Socket::Socket(RawSocketType sockfd, bool connected) :
        m_sockfd(sockfd), m_is_connected(connected)
    {
        Socket::getsockopt(sockfd, SOL_SOCKET, SO_TYPE, reinterpret_cast<SockOptType *>(&m_type), static_cast<socklen_t>(sizeof(int)));

#ifdef SO_DOMAIN
        // Fast path for Linux
        Socket::getsockopt(sockfd, SOL_SOCKET, SO_DOMAIN, &m_domain, static_cast<socklen_t>(sizeof(int)));
#else
        struct sockaddr_storage addr{};
        socklen_t len = sizeof(addr);
        if (getsockname(sockfd, reinterpret_cast<struct sockaddr *>(&addr), &len) == -1) {
            throw_errno_error("Failed to getsockname: ");
        }
        m_domain = addr.ss_family;
#endif

#ifdef SO_PROTOCOL
        // Fast path for Linux
        Socket::getsockopt(sockfd, SOL_SOCKET, SO_PROTOCOL, &m_protocol, static_cast<socklen_t>(sizeof(int)));
#elif defined (OS_WINDOWS)
        // Windows fallback using Protocol Info
        WSAPROTOCOL_INFO info;
        Socket::getsockopt(sockfd, SOL_SOCKET, SO_PROTOCOL_INFO, (char *)&info, sizeof(info));

        m_protocol = info.iProtocol;
#else
        if (m_domain == AF_INET || m_domain == AF_INET6) {
            if (m_type == SOCK_STREAM) {
                m_protocol = IPPROTO_TCP;
            } else if (m_type == SOCK_DGRAM) {
                m_protocol = IPPROTO_UDP;
            } else {
                m_protocol = -1;
            }
        }
#endif
    }

    // TODO: more error handling arround is_connected == false and sockfd == INVALID in IO calls
    Socket::Socket() :
        m_sockfd(INVALID_SOCKET) // TODO: Currently using this constructor results in an UNSUABLE socket.
                                 // That's bad -> fix it.
    {}

    Socket::Socket(int domain, int type, int protocol) :
        m_domain(domain), m_type(type), m_protocol(protocol), m_sockfd(INVALID_SOCKET)
    {
        this->create_socket();
    }

    Socket::~Socket() {
        try {
            close();
        } catch (const std::runtime_error &e) {
            std::cerr << e.what() << '\n';
        }
    }

    Socket::Socket(Socket &&other) noexcept :
        m_sockfd(INVALID_SOCKET)
    {
        *this = std::move(other);
    }

    auto Socket::operator=(Socket &&other) noexcept -> Socket & {
        std::swap(m_sockfd, other.m_sockfd);
        std::swap(m_domain, other.m_domain);
        std::swap(m_type, other.m_type);
        std::swap(m_protocol, other.m_protocol);
        std::swap(m_is_connected, other.m_is_connected);
        return *this;
    }

    void Socket::close() {
        if (m_sockfd != INVALID_SOCKET) {
            if (m_is_connected && m_type == SOCK_STREAM) {
                if (shutdown(m_sockfd, SHUT_RDWR) != 0) {
                    // log error instead of raising, errors shouldn't occur and if
                    // they do we still need to close() the FD.
                    std::cerr << "Failed to shutdown connection: " << CppSockets::strerror() << '\n';
                }
                m_is_connected = false;
            }

#ifdef OS_WINDOWS
            int res = closesocket(m_sockfd);
#else
            int res = ::close(m_sockfd);
#endif
            if (res != 0) {
                throw_errno_error("Failed to close socket: ");
            }

            m_sockfd = INVALID_SOCKET;
        }
    }

    auto Socket::read(std::size_t len) -> std::string {
        std::array<char, BUFF_SIZE> buff;
        std::size_t buff_size = buff.size();
        std::string res;
        std::size_t nb = 0;
        bool read_all_avail = len == static_cast<std::size_t>(-1);

        if (!read_all_avail)
            res.reserve(len);

        do {
            nb = this->read(buff.data(), read_all_avail ? buff_size : std::min(buff_size, len));

            if (nb == 0) {
                break;
            }
            res.append(buff.data(), nb);

            if (!read_all_avail) {
                len -= nb;
            }
        } while (read_all_avail ? this->has_more_data() : len != 0);
        return res;
    }

    auto Socket::read(char *buff, std::size_t size) -> std::size_t {
        std::ptrdiff_t ret;

        if (!m_is_connected)
            throw std::runtime_error("Not connected");
        ret = ::read(m_sockfd, buff, size);
        if (ret < 0) {
            int err = CppSockets::get_errno();

            if (err == SOCK_EAGAIN || err == SOCK_EWOULDBLOCK) {
                return 0;
            }
            throw_errno_error("Failed to read from socket: ");
        } else if (ret == 0 && size > 0) {
            m_is_connected = false;
        }
        return ret;
    }

    auto Socket::has_more_data() const -> bool {
        try {
            return static_cast<bool>(this->poll(PollEvent::READ));
        } catch (const std::runtime_error &) {
            // If poll errors now, something is wrong on the socket.
            // We return false to interupt the read loop, and return what we got,
            // and the error will be raised by the next I/O call.
            return false;
        }
    }

    auto Socket::write(const char *buff, std::size_t len) -> std::size_t { // NOLINT(readability-make-member-function-const)
        std::ptrdiff_t ret;

        if (!m_is_connected)
            throw std::runtime_error("Not connected");
        ret = ::write(m_sockfd, buff, len);
        if (ret < 0) {
            int err = CppSockets::get_errno();

            if (err == SOCK_EAGAIN || err == SOCK_EWOULDBLOCK) {
                return 0;
            }
            throw_errno_error("Failed to write to socket: ");
        }
        return ret;
    }

    auto Socket::set_reuseaddr(bool value) -> int {
        int val = static_cast<int>(value);

        return this->setsockopt(SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<SockOptType *>(&val), sizeof(val));
    }

    auto Socket::getsockopt(int level, int optname, SockOptType *optval, socklen_t *optlen) -> int { // NOLINT(readability-make-member-function-const)
        return CppSockets::Socket::getsockopt(m_sockfd, level, optname, optval, optlen);
    }

    auto Socket::setsockopt(int level, int optname, const SockOptType *optval, socklen_t optlen) -> int { // NOLINT(readability-make-member-function-const)
        int ret = ::setsockopt(m_sockfd, level, optname, optval, optlen);

        if (ret < 0)
            throw_errno_error("Failed to set socket option: ");
        return ret;
    }

    auto Socket::bind(const std::string &addr, uint16_t port) -> int {
        return this->bind(Endpoint<IPv4>(IPv4(addr.c_str()), port));
    }

    auto Socket::bind(const IEndpoint &endpoint) -> int {
        // TODO: this only works for IPv4. Need to switch getFamily() to handle
        // IPv6 / AF_UNIX ...
        if (endpoint.get_addr().get_family() != AF_INET)
            throw std::runtime_error("Only AF_INET endpoints are supported");
        return this->bind(endpoint.get_addr().get_address(), endpoint.get_port());
    }

    auto Socket::connect(const std::string &addr, uint16_t port) -> int {
        return this->connect(Endpoint<IPv4>(IPv4(addr.c_str()), port));
    }

    auto Socket::connect(const IEndpoint &endpoint) -> int {
        struct sockaddr_in addr = {0};
        auto &address = endpoint.get_addr();
        int ret = 0;

        if (m_domain != AF_INET)
            throw std::runtime_error("Socket is not an AF_INET socket");
        if (address.get_family() != AF_INET)
            throw std::runtime_error("Only AF_INET endpoints are supported");

        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = address.get_address();
        addr.sin_port = htons(endpoint.get_port());
        if (m_is_connected && m_type == SOCK_STREAM) {
            this->close(); // TCP cannot re-use socket (EISCONN), need to close first
        }
        if (m_sockfd == INVALID_SOCKET) {
            this->create_socket();
        }
        ret = ::connect(m_sockfd, reinterpret_cast<const struct sockaddr *>(&addr), sizeof(addr));
        if (ret < 0) {
            int connect_errno = CppSockets::get_errno();

            m_is_connected = false;
            // handle "in-progress" connect errors for non-blocking sockets
            if (connect_errno == SOCK_EINPROGRESS || connect_errno == SOCK_EALREADY) {
                return 0;
            } else if (connect_errno == SOCK_EISCONN) {
                m_is_connected = true;
                return 0;
            }
            try {
                this->close();
            } catch (const std::runtime_error &e) {
                std::cerr << "Exception while closing failed connect socket: " << e.what() << '\n';
            }

            throw_errno_error(std::string("Failed to connect socket to ") + endpoint.to_string() + " : ", connect_errno);
        } else {
            m_is_connected = true;
        }
        return ret;
    }

    auto Socket::listen(int backlog) -> int { // NOLINT(readability-make-member-function-const)
        int ret = ::listen(m_sockfd, backlog);

        if (ret < 0)
            throw_errno_error("Failed to listen socket: ");
        return ret;
    }

    auto Socket::accept() -> std::unique_ptr<Socket> {
        return std::unique_ptr<Socket>(acceptImpl(nullptr));
    }

    auto Socket::accept(sockaddr_storage &addr) -> std::unique_ptr<Socket> {
        return std::unique_ptr<Socket>(acceptImpl(&addr));
    }

    auto Socket::acceptImpl(sockaddr_storage *addr_out) -> Socket * { // NOLINT(readability-make-member-function-const)
        socklen_t addr_len = static_cast<socklen_t>(sizeof(sockaddr_storage));
        int fd = ::accept(m_sockfd, reinterpret_cast<struct sockaddr *>(addr_out), &addr_len);

        if (fd == INVALID_SOCKET) {
            int err = CppSockets::get_errno();

            if (err == SOCK_EAGAIN || err == SOCK_EWOULDBLOCK || err == SOCK_EINTR) {
                return nullptr;
            }
            throw_errno_error("Failed to accept: ", err);
        }
        return new Socket(fd, true);
    }

    void Socket::set_blocking(bool val) { // NOLINT(readability-make-member-function-const)
#ifdef OS_WINDOWS
        u_long mode = val ? 0 : 1;
        int result = ioctlsocket(m_sockfd, FIONBIO, &mode);
        if (result != NO_ERROR) {
            throw_errno_error("Failed to change socket blocking mode: ");
        }
#else
        int flags = fcntl(m_sockfd, F_GETFL, 0);
        int ret = flags;

        if (ret >= 0) {
            if (val) {
                ret = fcntl(m_sockfd, F_SETFL, flags & ~O_NONBLOCK); // NOLINT(cppcoreguidelines-pro-type-vararg, hicpp-vararg, hicpp-signed-bitwise)
            } else {
                ret = fcntl(m_sockfd, F_SETFL, flags | O_NONBLOCK); // NOLINT(cppcoreguidelines-pro-type-vararg, hicpp-vararg, hicpp-signed-bitwise)
            }
        }
        if (ret < 0) {
            throw_errno_error("Failed to change socket blocking mode: ");
        }
#endif
    }

    auto Socket::poll(PollEvent events, int timeout_ms) const -> PollEvent {
        PollfdType pfd{};
        int ret;

        pfd.fd = m_sockfd;
        if (events.has(PollEvent::READ)) pfd.events |= POLLIN;
        if (events.has(PollEvent::WRITE)) pfd.events |= POLLOUT;

#ifdef OS_WINDOWS
        ret = WSAPoll(&pfd, 1, timeout_ms);
#else
        ret = ::poll(&pfd, 1, timeout_ms);
#endif
        if (ret < 0) {
            throw_errno_error("Failed to poll socket: ");
        } else if (ret == 0) {
            return PollEvent::NONE;
        }

        if (pfd.revents & POLLNVAL) {
            throw std::runtime_error("Socket fd is not valid");
        }
        if (pfd.revents & POLLERR) {
            int sock_err = 0;

            Socket::getsockopt(m_sockfd, SOL_SOCKET, SO_ERROR, reinterpret_cast<SockOptType *>(&sock_err), static_cast<socklen_t>(sizeof(int)));
            throw_errno_error("Socket error: ", sock_err);
        }

        PollEvent result = PollEvent::NONE;

        if (pfd.revents & (POLLIN | POLLHUP)) result |= PollEvent::READ;
        if (pfd.revents & POLLOUT) result |= PollEvent::WRITE;

        return result & events;
    }

    auto Socket::getsockopt(int fd, int level, int optname, SockOptType *optval, socklen_t *optlen) -> int {
        int ret = ::getsockopt(fd, level, optname, optval, optlen);

        if (ret == SOCKET_ERROR)
            throw_errno_error("Failed to get sock opt: ");
        return ret;
    }

    auto Socket::bind(std::uint32_t source_addr, uint16_t port) -> int { // NOLINT(readability-make-member-function-const)
        struct sockaddr_in addr = {};
        int ret = 0;

        if (m_domain != AF_INET)
            throw std::runtime_error("Socket is not an AF_INET socket");
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = source_addr;
        addr.sin_port = htons(port);
        ret = ::bind(m_sockfd, reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr));

        if (ret < 0)
            throw_errno_error("Failed to bind socket: ");
        return ret;
    }

    void Socket::throw_errno_error(std::string message) {
        Socket::throw_errno_error(std::move(message), CppSockets::get_errno());
    }

    void Socket::throw_errno_error(std::string message, int err) {
        throw std::runtime_error(std::move(message) + CppSockets::strerror(err));
    }

    void Socket::create_socket() {
        m_sockfd = ::socket(m_domain, m_type, m_protocol);
        if (m_sockfd == INVALID_SOCKET) {
            throw_errno_error("Failed to create socket : ");
        }
    }
}
