/*
** Project CppSocket, 2022
**
** Author Francois Michaut
**
** Started on  Sat Jan 15 01:27:40 2022 Francois Michaut
** Last update Wed Sep 14 22:19:18 2022 Francois Michaut
**
** Socket.cpp : Protable C++ socket class implementation
*/

#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <unistd.h>

#ifdef _WIN32
#include <ws2tcpip.h>
#else
#include <fcntl.h>
#include <netinet/in.h>
 // To match windows's constants
static constexpr int INVALID_SOCKET = -1;
static constexpr int SOCKET_ERROR = -1;
#endif

static constexpr int BUFF_SIZE = 4096;

// TODO add exceptions on error retunrs
// TODO throw custom exceptions on invalid status (eg: socket already connected)
#include "CppSockets/IPv4.hpp"
#include "CppSockets/Socket.hpp"

namespace CppSockets {
    void Socket::init() {
#ifdef _WIN32
        static bool init_done = false;
        WSADATA wsa_data;

        if (!init_done) {
            // TODO need to call WSACleanup too
            if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
                throw std::runtime_error(std::string("WASStartup Failed : ") + std::strerror(errno));
            }
            init_done = true;
        }
#endif
    }

    Socket::Socket(int domain, int type, int protocol, int sockfd) :
        domain(domain), type(type), protocol(protocol), sockfd(sockfd)
    {
        init();
    }

    Socket::Socket(int domain, int type, int protocol) :
        domain(domain), type(type), protocol(protocol)
    {
        init();
        sockfd = ::socket(domain, type, protocol);
        if (sockfd == INVALID_SOCKET)
            throw std::runtime_error(std::string("Failed to create socket : ") + std::strerror(errno));
    }

    Socket::Socket(Socket &&other) noexcept { // NOLINT
        *this = std::move(other);
    }

    Socket &Socket::operator=(Socket &&other) noexcept {
        sockfd = other.sockfd;
        domain = other.domain;
        other.sockfd = INVALID_SOCKET;
        return *this;
    }

    Socket::~Socket() {
#ifdef _WIN32
        closesocket(raw_socket);
#else
        close(sockfd);
#endif
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
#ifdef _WIN32
#else
        return ::strerror(err);
#endif
    }

    int Socket::get_errno() {
#ifdef _WIN32
#else
        return errno;
#endif
    }

    std::string Socket::read(std::size_t len) {
        std::array<char, BUFF_SIZE> buff = {0};
        std::string res;
        std::size_t total = 0;
        std::size_t nb = 1;

        while (nb != 0 && (len == -1 || total < len)) {
            nb = ::read(sockfd, buff.data(), BUFF_SIZE);
            if (nb > 0) {
                res += std::string(buff.data(), nb);
            } else if (nb < 0) {
                throw std::runtime_error(std::string("Failed to read from socket: ") + Socket::strerror());
            }
        }
        return res;
    }

    std::size_t Socket::read(char *buff, std::size_t size) {
        std::size_t ret = ::read(sockfd, buff, size);

        if (ret < 0) {
            throw std::runtime_error(std::string("Failed to read from socket: ") + Socket::strerror());
        }
        return ret;
    }

    std::size_t Socket::write(const std::string &buff) {
        return this->write(buff.data(), buff.size());
    }

    std::size_t Socket::write(const char *buff, std::size_t len) {
        std::size_t ret = ::write(sockfd, buff, len);

        if (ret < 0) {
            throw std::runtime_error(std::string("Failed to write to socket: ") + Socket::strerror());
        }
        return ret;
    }

    int Socket::getsockopt(int level, int optname, void *optval, socklen_t *optlen) {
        return this->getsockopt(sockfd, level, optname, optval, optlen);
    }

    int Socket::setsockopt(int level, int optname, const void *optval, socklen_t optlen) {
        int ret = ::setsockopt(sockfd, level, optname, optval, optlen);

        if (ret < 0) {
            throw std::runtime_error(std::string("Failed to set sock opt: ") + Socket::strerror());
        }
        return ret;
    }

    int Socket::bind(const std::string &addr, int port) {
        return this->bind(inet_addr(addr.c_str()), port);
    }

    int Socket::bind(std::uint32_t s_addr, int port) {
        struct sockaddr_in addr = {};
        int ret = 0;

        addr.sin_family = domain;
        addr.sin_addr.s_addr = htonl(s_addr);
        addr.sin_port = htons(port);
        ret = ::bind(sockfd, (struct sockaddr *)&addr, sizeof(addr));
        if (ret < 0) {
            throw std::runtime_error(std::string("Failed to bind socket: ") + Socket::strerror());
        }
        return ret;
    }

    int Socket::connect(const std::string &addr, int port) {
        return this->connect(Endpoint<IPv4>(IPv4(addr.c_str()), port));
    }

    int Socket::connect(const IEndpoint &endpoint) {
        struct sockaddr_in addr = {0};
        int ret = 0;

        addr.sin_addr.s_addr = endpoint.getAddr().getAddress();
        addr.sin_port = htons(endpoint.getPort());
        addr.sin_family = endpoint.getAddr().getFamily();
        ret = ::connect(sockfd, (const struct sockaddr *)&addr, sizeof(addr));
        if (ret < 0) {
            throw std::runtime_error(std::string("Failed to connect socket to ") + endpoint.toString() + " : " + Socket::strerror());
        }
        is_connected = ret == 0;
        return ret;
    }

    bool Socket::connected() const {
        return is_connected;
    }

    int Socket::listen(int backlog) {
        int ret = ::listen(sockfd, backlog);

        if (ret < 0) {
            throw std::runtime_error(std::string("Failed to listen socket: ") + Socket::strerror());
        }
        return ret;
    }

    std::shared_ptr<Socket> Socket::accept(void *addr_out) {
        int fd = ::accept(sockfd, nullptr, nullptr);
        int domain = 0;
        int type = 0;
        int protocol = 0;
        socklen_t len = sizeof(int);

        if (addr_out != nullptr) {
            // TODO
        }
        if (fd == INVALID_SOCKET) {
            return nullptr;
        }
        Socket::getsockopt(sockfd, SOL_SOCKET, SO_DOMAIN, &domain, &len);
        Socket::getsockopt(sockfd, SOL_SOCKET, SO_TYPE, &type, &len);
        Socket::getsockopt(sockfd, SOL_SOCKET, SO_PROTOCOL, &protocol, &len);
        return std::shared_ptr<Socket>(new Socket(domain, type, protocol, fd));
    }

    void Socket::set_blocking(bool val) {
        int flags = fcntl(sockfd, F_GETFL, 0);
        int ret = flags;

        if (ret >= 0) {
            if (val) {
                ret = fcntl(sockfd, F_SETFL, flags | O_NONBLOCK); //NOLINT
            } else {
                ret = fcntl(sockfd, F_SETFL, (flags | O_NONBLOCK) ^ O_NONBLOCK); //NOLINT
            }
        }
        if (ret < 0) {
            throw std::runtime_error(std::string("Failed to bind socket: ") + Socket::strerror());
        }
    }

    int Socket::get_fd() const {
        return sockfd;
    }

    int Socket::get_domain() const {
        return domain;
    }

    int Socket::get_protocol() const {
        return protocol;
    }

    int Socket::get_type() const {
        return type;
    }
}
