/*
** Project CppSocket, 2022
**
** Author Francois Michaut
**
** Started on  Sat Jan 15 01:27:40 2022 Francois Michaut
** Last update Sat Dec  2 17:11:28 2023 Francois Michaut
**
** Socket.cpp : Protable C++ socket class implementation
*/

#include "CppSockets/IPv4.hpp"
#include "CppSockets/OSDetection.hpp"
#include "CppSockets/Socket.hpp"

#ifdef OS_WINDOWS
  #include <ws2tcpip.h>
  #include <io.h>
#else
  #include <fcntl.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
  #include <unistd.h>

  // To match windows's constants
  static constexpr int INVALID_SOCKET = -1;
  static constexpr int SOCKET_ERROR = -1;
#endif

static constexpr int BUFF_SIZE = 4096;

#include <array>
#include <cerrno>
#include <cstring>
#include <sstream>
#include <stdexcept>


// TODO add exceptions on error retunrs
// TODO throw custom exceptions on invalid status (eg: socket already connected)
namespace CppSockets {
    Socket::Socket(RawSocketType sockfd, bool connected) :
        m_sockfd(sockfd), m_is_connected(connected)
    {
        socklen_t len = sizeof(int);

        Socket::getsockopt(sockfd, SOL_SOCKET, SO_TYPE, &m_type, &len);
#if !defined (OS_APPLE) && !defined (OS_WINDOWS)
        Socket::getsockopt(sockfd, SOL_SOCKET, SO_DOMAIN, &m_domain, &len);
        Socket::getsockopt(sockfd, SOL_SOCKET, SO_PROTOCOL, &m_protocol, &len);
#endif
    }

    // TODO: more error handling arround is_connected == false and sockfd == INVALID in IO calls
    Socket::Socket() :
        m_sockfd(INVALID_SOCKET)
    {}

    Socket::Socket(int domain, int type, int protocol) :
        m_domain(domain), m_type(type), m_protocol(protocol), m_sockfd(::socket(domain, type, protocol))
    {
        if (m_sockfd == INVALID_SOCKET)
            throw std::runtime_error(std::string("Failed to create socket : ") + std::strerror(errno));
    }

    Socket::Socket(Socket &&other) noexcept :
        m_sockfd(INVALID_SOCKET)
    {
        *this = std::move(other);
    }

    Socket &Socket::operator=(Socket &&other) noexcept {
        if (&other == this)
            return *this;
        this->close();

        m_sockfd = other.m_sockfd;
        m_domain = other.m_domain;
        other.m_sockfd = INVALID_SOCKET;
        m_is_connected = other.m_is_connected;
        return *this;
    }

    void Socket::close() {
        if (m_sockfd != INVALID_SOCKET) {
#ifdef OS_WINDOWS
            closesocket(m_sockfd);
#else
            ::close(m_sockfd);
#endif
        }
    }

    Socket::~Socket() {
        close();
    }

    int Socket::getsockopt(int fd, int level, int optname, void *optval, socklen_t *optlen) {
        int ret =  ::getsockopt(fd, level, optname, optval, optlen);

        if (ret == SOCKET_ERROR) {
            throw std::runtime_error(std::string("Failed to get sock opt: ") + Socket::strerror());
        }
        return ret;
    }

    char *Socket::strerror() {
        return Socket::strerror(Socket::get_errno());
    }

    char *Socket::strerror(int err) {
#ifdef OS_WINDOWS
#else
        return ::strerror(err);
#endif
    }

    int Socket::get_errno() {
#ifdef OS_WINDOWS
#else
        return errno;
#endif
    }

    std::string Socket::read(std::size_t len) {
        std::array<char, BUFF_SIZE> buff = {0};
        std::stringstream res;
        std::size_t total = 0;
        std::size_t nb = 1;

        while (nb != 0 && (len == -1 || total < len)) {
            nb = this->read(buff.data(), BUFF_SIZE);
            if (nb > 0) {
                res << std::string(buff.data(), nb);
            }
        }
        return res.str();
    }

    std::size_t Socket::read(char *buff, std::size_t size) {
        std::size_t ret;

        if (!m_is_connected)
            throw std::runtime_error("Not connected");
        ret = ::read(m_sockfd, buff, size);
        if (ret < 0) {
            throw std::runtime_error(std::string("Failed to read from socket: ") + Socket::strerror());
        } else if (ret == 0 && size > 0) {
            m_is_connected = false;
        }
        return ret;
    }

    std::size_t Socket::write(const std::string &buff) {
        return this->write(buff.data(), buff.size());
    }

    std::size_t Socket::write(const char *buff, std::size_t len) {
        std::size_t ret;

        if (!m_is_connected)
            throw std::runtime_error("Not connected");
        ret = ::write(m_sockfd, buff, len);
        if (ret < 0) {
            throw std::runtime_error(std::string("Failed to write to socket: ") + Socket::strerror());
        }
        return ret;
    }

    int Socket::set_reuseaddr(bool value) {
        int val = value;

        return this->setsockopt(SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));
    }

    int Socket::getsockopt(int level, int optname, void *optval, socklen_t *optlen) {
        return this->getsockopt(m_sockfd, level, optname, optval, optlen);
    }

    int Socket::setsockopt(int level, int optname, const void *optval, socklen_t optlen) {
        int ret = ::setsockopt(m_sockfd, level, optname, optval, optlen);

        if (ret < 0) {
            throw std::runtime_error(std::string("Failed to set sock opt: ") + Socket::strerror());
        }
        return ret;
    }

    int Socket::bind(const std::string &addr, uint16_t port) {
        return this->bind(inet_addr(addr.c_str()), port);
    }

    int Socket::bind(const IEndpoint &endpoint) {
        // TODO: this only works for IPv4. Need to switch getFamily() to handle IPv6 / AF_UNIX ...
        return this->bind(endpoint.getAddr().getAddress(), endpoint.getPort());
    }

    int Socket::bind(std::uint32_t source_addr, uint16_t port) {
        struct sockaddr_in addr = {};
        int ret = 0;

        addr.sin_family = m_domain;
        addr.sin_addr.s_addr = source_addr;
        addr.sin_port = htons(port);
        ret = ::bind(m_sockfd, (struct sockaddr *)&addr, sizeof(addr));
        if (ret < 0) {
            throw std::runtime_error(std::string("Failed to bind socket: ") + Socket::strerror());
        }
        return ret;
    }

    int Socket::connect(const std::string &addr, uint16_t port) {
        return this->connect(Endpoint<IPv4>(IPv4(addr.c_str()), port));
    }

    int Socket::connect(const IEndpoint &endpoint) {
        struct sockaddr_in addr = {0};
        int ret = 0;

        addr.sin_addr.s_addr = endpoint.getAddr().getAddress();
        addr.sin_port = htons(endpoint.getPort());
        addr.sin_family = endpoint.getAddr().getFamily();
        ret = ::connect(m_sockfd, (const struct sockaddr *)&addr, sizeof(addr));
        if (ret < 0) {
            throw std::runtime_error(std::string("Failed to connect socket to ") + endpoint.toString() + " : " + Socket::strerror());
        }
        m_is_connected = ret == 0;
        return ret;
    }

    bool Socket::connected() const {
        return m_is_connected;
    }

    int Socket::listen(int backlog) {
        int ret = ::listen(m_sockfd, backlog);

        if (ret < 0) {
            throw std::runtime_error(std::string("Failed to listen socket: ") + Socket::strerror());
        }
        return ret;
    }

    std::shared_ptr<Socket> Socket::accept(void *addr_out) {
        int fd = ::accept(m_sockfd, nullptr, nullptr);
        int domain = 0;
        int type = 0;
        int protocol = 0;

        if (addr_out != nullptr) {
            // TODO figure it out
        }
        if (fd == INVALID_SOCKET) {
            return nullptr;
        }
        return std::shared_ptr<Socket>(new Socket(fd, true));
    }

    void Socket::set_blocking(bool val) {
        int flags = fcntl(m_sockfd, F_GETFL, 0);
        int ret = flags;

        if (ret >= 0) {
            if (val) {
                ret = fcntl(m_sockfd, F_SETFL, flags | O_NONBLOCK); // NOLINT(cppcoreguidelines-pro-type-vararg, hicpp-vararg, hicpp-signed-bitwise)
            } else {
                ret = fcntl(m_sockfd, F_SETFL, (flags | O_NONBLOCK) ^ O_NONBLOCK); // NOLINT(cppcoreguidelines-pro-type-vararg, hicpp-vararg, hicpp-signed-bitwise)
            }
        }
        if (ret < 0) {
            throw std::runtime_error(std::string("Failed to change socket: ") + Socket::strerror());
        }
    }

    RawSocketType Socket::get_fd() const {
        return m_sockfd;
    }

    int Socket::get_domain() const {
        return m_domain;
    }

    int Socket::get_protocol() const {
        return m_protocol;
    }

    int Socket::get_type() const {
        return m_type;
    }
}
