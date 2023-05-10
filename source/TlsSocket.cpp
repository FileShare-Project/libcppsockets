/*
** Project LibFileShareProtocol, 2022
**
** Author Francois Michaut
**
** Started on  Wed Sep 14 21:04:42 2022 Francois Michaut
** Last update Tue May  9 23:34:24 2023 Francois Michaut
**
** SecureSocket.cpp : TLS socket wrapper implementation
*/

#include "CppSockets/OSDetection.hpp"
#include "CppSockets/TlsSocket.hpp"

#ifdef OS_WINDOWS
// TODO Currently disabling TlsSocket for windows
#else

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <sstream>
#include <stdexcept>

static constexpr int BUFF_SIZE = 4096;

// TODO use custom exceptions
namespace CppSockets {
    static void init_ssl_socket(SSL *ssl, SSL_CTX *ctx, TlsSocket *socket) {
        int success = 1;

        if (!ctx || !ssl || !SSL_set_fd(ssl, socket->get_fd())) {
            throw std::runtime_error(std::string("Failed to initialize TLS socket: ") + socket->tls_strerror(0));
        }
        success = success && SSL_CTX_set_min_proto_version(ctx, TLS1_VERSION);
        success = success && SSL_set_min_proto_version(ssl, TLS1_VERSION);
        if (!success) {
            throw std::runtime_error(std::string("Failed to select TLS version: ") + socket->tls_strerror(0));
        }
    }

    // TODO check if base destroctor is called (need to close the socket if error is raised)
    // TODO check if needs to call SSL_shutdown in such cases
    TlsSocket::TlsSocket(int domain, int type, int protocol) :
        CppSockets::Socket(domain, type, protocol),
        ctx(SSL_CTX_new(TLS_method()), SSL_CTX_free),
        ssl((ctx ? SSL_new(ctx.get()) : nullptr), SSL_free),
        peer_cert(nullptr, X509_free)
    {
        init_ssl_socket(ssl.get(), ctx.get(), this);
    }

    TlsSocket::TlsSocket(Socket &&other) :
        CppSockets::Socket(std::move(other)),
        ctx(SSL_CTX_new(TLS_method()), SSL_CTX_free),
        ssl(SSL_new(ctx.get()), SSL_free),
        peer_cert(nullptr, X509_free)
    {
        init_ssl_socket(ssl.get(), ctx.get(), this);
    }

    TlsSocket::~TlsSocket() {
        if (do_shutdown && ssl) {
            SSL_shutdown(ssl.get());
        }
    }

    TlsSocket::TlsSocket(TlsSocket &&other) noexcept :
        Socket(std::move(other)), ctx(std::move(other.ctx)),
        ssl(std::move(other.ssl)), peer_cert(std::move(other.peer_cert)),
        do_shutdown(other.do_shutdown)
    {}

    TlsSocket &TlsSocket::operator=(TlsSocket &&other) noexcept
    {
        ctx = std::move(other.ctx);
        ssl = std::move(other.ssl);
        peer_cert = std::move(other.peer_cert);
        do_shutdown = other.do_shutdown;

        Socket::operator=(std::move(other));
        return *this;
    }

    // TODO add SSL_get_shutdown checks in read operations
    std::string TlsSocket::read(std::size_t len) {
        std::array<char, BUFF_SIZE> buff = {0};
        std::stringstream res;
        std::size_t total = SSL_pending(ssl.get());
        std::size_t nb = 0;

        while (total != 0 && len != 0) {
            if (!SSL_read_ex(ssl.get(), buff.data(), (BUFF_SIZE > len ? len : BUFF_SIZE), &nb)) {
                throw std::runtime_error(std::string("Failed to read from socket: ") + TlsSocket::tls_strerror(0));
            }
            res << std::string(buff.data(), nb);
            total -= nb;
            if (len != -1)
                len -= nb;
        }
        return res.str();
    }

    std::size_t TlsSocket::read(char *buff, std::size_t size) {
        std::size_t nb = 0;

        if (!SSL_read_ex(ssl.get(), buff, size, &nb)) {
            throw std::runtime_error(std::string("Failed to read from socket: ") + TlsSocket::tls_strerror(0));
        }
        return nb;
    }

    std::size_t TlsSocket::write(const char *buff, std::size_t len) {
        std::size_t nb = 0;

        if (!SSL_read_ex(ssl.get(), (void *)buff, len, &nb)) {
            throw std::runtime_error(std::string("Failed to read from socket: ") + TlsSocket::tls_strerror(0));
        }
        return nb;
    }

    int TlsSocket::connect(const IEndpoint &endpoint) {
        int ret = Socket::connect(endpoint);
        int ssl_ret = SSL_connect(ssl.get());

        if (ssl_ret != 1) {
            throw std::runtime_error(std::string("Failed to connect: ") + TlsSocket::tls_strerror(ssl_ret));
        }
        peer_cert.reset(SSL_get_peer_certificate(ssl.get()));
        return ret;
    }

    std::shared_ptr<TlsSocket> TlsSocket::accept(void *addr_out) {
        auto res = Socket::accept(addr_out);
        std::shared_ptr<TlsSocket> tls;
        int ssl_ret = 0;

        if (!res)
            return nullptr;
        tls = std::make_shared<TlsSocket>(std::move(*res));
        ssl_ret = SSL_accept(tls->get_ssl().get());
        if (ssl_ret <= 0) {
            throw std::runtime_error("Failed to accept TLS connection: " + TlsSocket::tls_strerror(ssl_ret));
        }
        tls->peer_cert.reset(SSL_get_peer_certificate(ssl.get()));
        return tls;
    }

    static std::string extract_errors_from_queue() {
        auto error = ERR_get_error();
        std::stringstream ss;

        while (error != 0) {
            ss << ERR_error_string(error, nullptr);
            error = ERR_get_error();
            if (error != 0) {
                ss << '\n';
            }
        }
        return ss.str();
    }

    const std::string TlsSocket::tls_strerror(int ret) {
        int err = SSL_get_error(ssl.get(), ret);

        switch (err) {
            case SSL_ERROR_NONE:
                return "No error";
            case SSL_ERROR_ZERO_RETURN:
                return "Peer closed TLS connection";
            case SSL_ERROR_WANT_READ:
                return "Retry the operation later: WANT_READ";
            case SSL_ERROR_WANT_WRITE:
                return "Retry the operation later: WANT_WRITE";
            case SSL_ERROR_WANT_CONNECT:
                return "Retry the operation later: WANT_CONNECT";
            case SSL_ERROR_WANT_ACCEPT:
                return "Retry the operation later: WANT_ACCEPT";
            case SSL_ERROR_WANT_X509_LOOKUP:
                return "Retry the operation later: WANT_X509_LOOKUP";
            case SSL_ERROR_WANT_ASYNC:
                return "Retry the operation later: WANT_ASYNC";
            case SSL_ERROR_WANT_ASYNC_JOB:
                return "Retry the operation later: WANT_ASYNC_JOB";
            case SSL_ERROR_WANT_CLIENT_HELLO_CB:
                return "Retry the operation later: WANT_CLIENT_HELLO_CB";
            case SSL_ERROR_SYSCALL:
                do_shutdown = false;
                return std::string("Fatal system error: ") + Socket::strerror() + '\n' + extract_errors_from_queue();
            case SSL_ERROR_SSL:
                do_shutdown = false;
                return  "Fatal TLS error: " + extract_errors_from_queue();
            default:
                return "Unknown error: " + std::to_string(err) + '\n' + extract_errors_from_queue();
        }
    }
}
#endif
