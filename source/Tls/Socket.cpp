/*
** Project LibFileShareProtocol, 2022
**
** Author Francois Michaut
**
** Started on  Wed Sep 14 21:04:42 2022 Francois Michaut
** Last update Fri Aug 22 21:57:23 2025 Francois Michaut
**
** SecureSocket.cpp : TLS socket wrapper implementation
*/

#include "CppSockets/OSDetection.hpp"
#include "CppSockets/Tls/Context.hpp"
#include "CppSockets/Tls/Socket.hpp"
#include "CppSockets/Tls/Utils.hpp"

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <array>
#include <sstream>
#include <stdexcept>

static constexpr int BUFF_SIZE = 4096;

namespace  {
    auto extract_errors_from_queue() -> std::string {
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

    void init_ssl_socket(SSL *ssl, CppSockets::TlsSocket *socket) {
        if (!ssl || !SSL_set_fd(ssl, socket->get_fd())) {
            throw std::runtime_error(std::string("Failed to initialize TLS socket: ") + socket->tls_strerror(0));
        }
        if (!SSL_set_min_proto_version(ssl, TLS1_VERSION)) {
            throw std::runtime_error(std::string("Failed to select TLS version: ") + socket->tls_strerror(0));
        }
    }
}

// TODO use custom exceptions
namespace CppSockets {
    // TODO check if base destroctor is called (need to close the socket if error is raised)
    // TODO check if needs to call SSL_shutdown in such cases
    TlsSocket::TlsSocket(int domain, int type, int protocol, TlsContext ctx) :
        CppSockets::Socket(domain, type, protocol),
        m_ctx(std::move(ctx)), m_ssl((SSL_new(m_ctx.get()))), m_peer_cert(nullptr)
    {
        init_ssl_socket(m_ssl.get(), this);
    }

    TlsSocket::TlsSocket(Socket &&other, TlsContext ctx) :
        CppSockets::Socket(std::move(other)), // TODO: if socket is not connected, at that moment, does it break ?
        m_ctx(std::move(ctx)), m_ssl(SSL_ptr(SSL_new(m_ctx.get()))), m_peer_cert(nullptr)
    {
        init_ssl_socket(m_ssl.get(), this);
    }

    TlsSocket::TlsSocket(Socket &&other, SSL_ptr ssl) :
        CppSockets::Socket(std::move(other)), // TODO: if socket is not connected, at that moment, does it break ?
        m_ctx({ssl ? SSL_get_SSL_CTX(ssl.get()) : SSL_CTX_new(TLS_method()), !ssl}),
        m_ssl(ssl ? std::move(ssl) : SSL_ptr(SSL_new(m_ctx.get()))),
        m_peer_cert(nullptr)
    {
        init_ssl_socket(m_ssl.get(), this);
    }

    TlsSocket::~TlsSocket() noexcept {
        if (m_ssl && this->connected()) {
            // TODO: Better shutdown mecanics
            int ret = SSL_shutdown(m_ssl.get());

            // if (ret == 1) {
            //     // Peer also closed -> We can leave.
            // } else if (ret == 0) {
            //     // Peer didn't send, but we can't wait in the Destructor
            // } else {
            //     // TODO: log failure
            // }
        }
    }

    TlsSocket::TlsSocket(TlsSocket &&other) noexcept {
        *this = std::move(other);
    }

    auto TlsSocket::operator=(TlsSocket &&other) noexcept -> TlsSocket & {
        m_ssl = std::move(other.m_ssl);
        m_ctx = std::move(other.m_ctx);
        m_peer_cert = std::move(other.m_peer_cert);

        Socket::operator=(std::move(other));
        return *this;
    }

    void TlsSocket::close() {
        int ret = SSL_shutdown(m_ssl.get());

        if (ret == 1) {
            return Socket::close();
        }
        // if (ret == 0) {
        //     // TODO: wait for peer
        // } else {
        //     // TODO: Log failure
        // }
    }

    void TlsSocket::set_verify(int mode, SSL_verify_cb verify_callback) {
        // TODO: While setting it on the CTX makes sense imo (since accepted sockets will inherit this), an application
        // might not want that behavior. Need to provide alertnate ways to set verify on CTX vs SSL
        SSL_CTX_set_verify(m_ctx.get(), mode, verify_callback);
    }

    void TlsSocket::set_certificate(const std::string &cert_path, const std::string &pkey_path) {
        BIO_ptr cert(BIO_new_file(cert_path.c_str(), "r"));
        BIO_ptr pkey(BIO_new_file(pkey_path.c_str(), "r"));
        // TODO: handle pkey password: SSL_set_default_passwd_cb or PEM_read_bio_X509 last 2 args
        X509_ptr x509(PEM_read_bio_X509(cert.get(), nullptr, nullptr, nullptr));
        EVP_PKEY_ptr evp_pkey(PEM_read_bio_PrivateKey(pkey.get(), nullptr, nullptr, nullptr));

        if (SSL_use_certificate(m_ssl.get(), x509.get()) <= 0) {
            throw std::runtime_error(std::string("Failed to set certificate: ") + TlsSocket::tls_strerror(0));
        }

        if (SSL_use_PrivateKey(m_ssl.get(), evp_pkey.get()) <= 0 ) {
            throw std::runtime_error(std::string("Failed to set private key: ") + TlsSocket::tls_strerror(0));
        }
    }

    // TODO add SSL_get_shutdown checks in read operations
    auto TlsSocket::read(std::size_t len) -> std::string {
        std::array<char, BUFF_SIZE> buff = {0};
        std::stringstream res;
        std::size_t nb = 0;
        std::size_t total;

        if (SSL_peek(m_ssl.get(), buff.data(), buff.size()) <= 0) {
            set_connected(false); // TODO: we should replace this with check_for_error
        }
        check_for_error("Failed to read from socket", 1); // Do not raise an error if peek failed
        total = SSL_pending(m_ssl.get());
        while (total != 0 && len != 0) {
            nb = this->read(buff.data(), (buff.size() > len ? len : buff.size()));
            res << std::string(buff.data(), nb);
            total -= nb;
            if (len != -1)
                len -= nb;
        }
        return res.str();
    }

    auto TlsSocket::read(char *buff, std::size_t size) -> std::size_t {
        std::size_t nb = 0;
        int ret = SSL_read_ex(m_ssl.get(), buff, size, &nb);

        check_for_error("Failed to read from socket: ", ret);
        return nb;
    }

    auto TlsSocket::write(const char *buff, std::size_t len) -> std::size_t {
        std::size_t nb = 0;
        int ret = SSL_write_ex(m_ssl.get(), static_cast<const void *>(buff), len, &nb);

        check_for_error("Failed to write to socket: ", ret);
        return nb;
    }

    void TlsSocket::check_for_error(const std::string &error_msg, int ret) {
        int shutdown = SSL_get_shutdown(m_ssl.get());

        if (shutdown == SSL_RECEIVED_SHUTDOWN) {
            SSL_shutdown(m_ssl.get()); // TODO: log failure
            set_connected(false);
        }

        if (ret <= 0) {
            throw std::runtime_error(error_msg + TlsSocket::tls_strerror(ret));
        }
    }

    auto TlsSocket::connect(const IEndpoint &endpoint) -> int {
        int ret = Socket::connect(endpoint);
        int ssl_ret = SSL_connect(m_ssl.get());

        if (ssl_ret != 1) {
            throw std::runtime_error(std::string("Failed to connect: ") + TlsSocket::tls_strerror(ssl_ret));
        }
        m_peer_cert.reset(SSL_get_peer_certificate(m_ssl.get()));
        return ret;
    }

    auto TlsSocket::accept(void *addr_out, TlsContext ctx) -> std::unique_ptr<TlsSocket> {
        std::unique_ptr<Socket> res = Socket::accept(addr_out);
        std::unique_ptr<TlsSocket> tls;
        int ssl_ret = 0;

        if (!res) {
            return nullptr;
        }

        tls = std::make_unique<TlsSocket>(std::move(*res), std::move(ctx));
        ssl_ret = SSL_accept(tls->get_ssl().get());
        if (ssl_ret <= 0) {
            throw std::runtime_error("Failed to accept TLS connection: " + TlsSocket::tls_strerror(ssl_ret));
        }
        tls->m_peer_cert.reset(SSL_get_peer_certificate(tls->get_ssl().get()));
        return tls;
    }

    auto TlsSocket::get_ssl_ctx() const -> TlsContext {
        return {SSL_get_SSL_CTX(m_ssl.get()), false};
    }

    auto TlsSocket::tls_strerror(int ret) -> std::string {
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
                set_connected(false);
                return std::string("Fatal system error: ") + Socket::strerror() + '\n' + extract_errors_from_queue();
            case SSL_ERROR_SSL:
                set_connected(false);
                return  "Fatal TLS error: " + extract_errors_from_queue();
            default:
                return "Unknown error: " + std::to_string(err) + '\n' + extract_errors_from_queue();
        }
    }
}
