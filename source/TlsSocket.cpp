/*
** Project LibFileShareProtocol, 2022
**
** Author Francois Michaut
**
** Started on  Wed Sep 14 21:04:42 2022 Francois Michaut
** Last update Sat Dec  2 11:33:00 2023 Francois Michaut
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

#include <array>
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
        m_ctx(SSL_CTX_new(TLS_method()), SSL_CTX_free),
        m_ssl((m_ctx ? SSL_new(m_ctx.get()) : nullptr), SSL_free),
        m_peer_cert(nullptr, X509_free),
        m_cert(nullptr, X509_free),
        m_pkey(nullptr, EVP_PKEY_free)
    {
        init_ssl_socket(m_ssl.get(), m_ctx.get(), this);
    }

    // TlsSocket::TlsSocket(RawSocketType fd, SSL_ptr ssl) :
    //     CppSockets::Socket(fd),
    //     m_ctx((ssl ? SSL_get_SSL_CTX(ssl.get()) : SSL_CTX_new(TLS_method())), SSL_CTX_free),
    //     m_ssl(ssl ? std::move(ssl) : (m_ctx ? SSL_ptr(SSL_new(m_ctx.get()), SSL_free) : nullptr)),
    //     m_peer_cert(nullptr, X509_free),
    //     m_cert(nullptr, X509_free),
    //     m_pkey(nullptr, EVP_PKEY_free)
    // {
    //     init_ssl_socket(m_ssl.get(), m_ctx.get(), this);
    // }

    TlsSocket::TlsSocket(Socket &&other, SSL_ptr ssl) :
        CppSockets::Socket(std::move(other)), // TODO: if socket is not connected, at that moment, does it break ?
        m_ctx((ssl ? SSL_get_SSL_CTX(ssl.get()) : SSL_CTX_new(TLS_method())), SSL_CTX_free),
        m_ssl(ssl ? std::move(ssl) : (m_ctx ? SSL_ptr(SSL_new(m_ctx.get()), SSL_free) : nullptr)),
        m_peer_cert(nullptr, X509_free),
        m_cert(nullptr, X509_free),
        m_pkey(nullptr, EVP_PKEY_free)
    {
        init_ssl_socket(m_ssl.get(), m_ctx.get(), this);
    }

    TlsSocket::~TlsSocket() {
        if (m_ssl && m_is_connected) {
            int ret = SSL_shutdown(m_ssl.get()); // TODO: log failure

            if (ret == 0) {
                while (m_is_connected) {
                    this->read();
                }
                SSL_shutdown(m_ssl.get()); // TODO: log failure
            }
        }
    }

    TlsSocket::TlsSocket(TlsSocket &&other) noexcept :
        Socket(std::move(other)), m_ctx(std::move(other.m_ctx)),
        m_ssl(std::move(other.m_ssl)), m_peer_cert(std::move(other.m_peer_cert)),
        m_cert(std::move(other.m_cert)), m_pkey(std::move(other.m_pkey))
    {}

    TlsSocket &TlsSocket::operator=(TlsSocket &&other) noexcept
    {
        m_ctx = std::move(other.m_ctx);
        m_ssl = std::move(other.m_ssl);
        m_peer_cert = std::move(other.m_peer_cert);
        m_cert = std::move(other.m_cert);
        m_pkey = std::move(other.m_pkey),

        Socket::operator=(std::move(other));
        return *this;
    }

    void TlsSocket::set_certificate(std::string cert_path, std::string pkey_path) {
        BIO_ptr cert(BIO_new_file(cert_path.c_str(), "r"), BIO_free);
        BIO_ptr pkey(BIO_new_file(pkey_path.c_str(), "r"), BIO_free);
        // TODO: handle pkey password: SSL_CTX_set_default_passwd_cb
        X509_ptr x509(PEM_read_bio_X509(cert.get(), nullptr, nullptr, nullptr), X509_free);
        EVP_PKEY_ptr evp_pkey(PEM_read_bio_PrivateKey(pkey.get(), nullptr, nullptr, nullptr), EVP_PKEY_free);

        if (SSL_CTX_use_certificate(m_ctx.get(), x509.get()) <= 0) {
            throw std::runtime_error(std::string("Failed to set certificate: ") + TlsSocket::tls_strerror(0));
        }
        m_cert = std::move(x509);

        if (SSL_CTX_use_PrivateKey(m_ctx.get(), evp_pkey.get()) <= 0 ) {
            throw std::runtime_error(std::string("Failed to set private key: ") + TlsSocket::tls_strerror(0));
        }
        m_pkey = std::move(evp_pkey);
    }

    // TODO add SSL_get_shutdown checks in read operations
    std::string TlsSocket::read(std::size_t len) {
        std::array<char, BUFF_SIZE> buff = {0};
        std::stringstream res;
        std::size_t nb = 0;
        std::size_t total;

        if (SSL_peek(m_ssl.get(), buff.data(), BUFF_SIZE) <= 0) {
            m_is_connected = false; // TODO: we should replace this with check_for_error
        }
        check_for_error("Failed to read from socket", 1); // Do not raise an error if peek failed
        total = SSL_pending(m_ssl.get());
        while (total != 0 && len != 0) {
            nb = this->read(buff.data(), (BUFF_SIZE > len ? len : BUFF_SIZE));
            res << std::string(buff.data(), nb);
            total -= nb;
            if (len != -1)
                len -= nb;
        }
        return res.str();
    }

    std::size_t TlsSocket::read(char *buff, std::size_t size) {
        std::size_t nb = 0;
        int ret = SSL_read_ex(m_ssl.get(), buff, size, &nb);

        check_for_error("Failed to read from socket: ", ret);
        return nb;
    }

    std::size_t TlsSocket::write(const char *buff, std::size_t len) {
        std::size_t nb = 0;
        int ret = SSL_write_ex(m_ssl.get(), (void *)buff, len, &nb);

        check_for_error("Failed to write to socket: ", ret);
        return nb;
    }

    void TlsSocket::check_for_error(std::string error_msg, int ret) {
        int shutdown = SSL_get_shutdown(m_ssl.get());

        if (shutdown == SSL_RECEIVED_SHUTDOWN) {
            SSL_shutdown(m_ssl.get()); // TODO: log failure
            m_is_connected = false;
        }

        if (ret <= 0) {
            throw std::runtime_error(error_msg + TlsSocket::tls_strerror(ret));
        }
    }

    int TlsSocket::connect(const IEndpoint &endpoint) {
        int ret = Socket::connect(endpoint);
        int ssl_ret = SSL_connect(m_ssl.get());

        if (ssl_ret != 1) {
            throw std::runtime_error(std::string("Failed to connect: ") + TlsSocket::tls_strerror(ssl_ret));
        }
        m_peer_cert.reset(SSL_get_peer_certificate(m_ssl.get()));
        return ret;
    }

    std::shared_ptr<TlsSocket> TlsSocket::accept(void *addr_out) {
        auto res = Socket::accept(addr_out);
        std::shared_ptr<TlsSocket> tls;
        int ssl_ret = 0;

        if (!res)
            return nullptr;
        if (SSL_CTX_up_ref(m_ctx.get()) == 0) {
            throw  std::runtime_error("Failed to DUP SSL_CTX: " + TlsSocket::tls_strerror(0));
        }

        tls = std::make_shared<TlsSocket>(std::move(*res), SSL_ptr(SSL_new(m_ctx.get()), SSL_free));
        ssl_ret = SSL_accept(tls->get_ssl().get());
        if (ssl_ret <= 0) {
            throw std::runtime_error("Failed to accept TLS connection: " + TlsSocket::tls_strerror(ssl_ret));
        }
        tls->m_peer_cert.reset(SSL_get_peer_certificate(m_ssl.get()));
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
        int err = SSL_get_error(m_ssl.get(), ret);

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
                m_is_connected = false;
                return std::string("Fatal system error: ") + Socket::strerror() + '\n' + extract_errors_from_queue();
            case SSL_ERROR_SSL:
                m_is_connected = false;
                return  "Fatal TLS error: " + extract_errors_from_queue();
            default:
                return "Unknown error: " + std::to_string(err) + '\n' + extract_errors_from_queue();
        }
    }
}
#endif
