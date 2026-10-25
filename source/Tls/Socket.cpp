/*
** Project LibCppSockets, 2022
**
** Author Francois Michaut
**
** Started on  Wed Sep 14 21:04:42 2022 Francois Michaut
** Last update Mon Oct 26 21:38:10 2026 Francois Michaut
**
** SecureSocket.cpp : TLS socket wrapper implementation
*/

#include "CppSockets/OSDetection.hpp"
#include "CppSockets/SocketInternals.hpp"
#include "CppSockets/Tls/Context.hpp"
#include "CppSockets/Tls/Socket.hpp"
#include "CppSockets/Tls/Utils.hpp"

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509_vfy.h>

#include <algorithm>
#include <iostream>
#include <stdexcept>

namespace {
    void init_ssl_socket(SSL *ssl, CppSockets::TlsSocket *socket) {
        if (!ssl) {
            throw std::runtime_error("Failed to initialize TLS socket: " + CppSockets::openssl_extract_errors_from_stack());
        }
        if (!SSL_set_fd(ssl, socket->get_fd())) {
            throw std::runtime_error(std::string("Failed to initialize TLS socket: ") + CppSockets::ssl_strerror(socket->tls_errno(0)));
        }
        if (!SSL_set_min_proto_version(ssl, TLS1_2_VERSION)) {
            throw std::runtime_error(std::string("Failed to select TLS version: ") + CppSockets::ssl_strerror(socket->tls_errno(0)));
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

    TlsSocket::TlsSocket(TlsSocket &&other) noexcept :
        Socket(std::move(other)), m_ctx(std::move(other.m_ctx)),
        m_ssl(std::move(other.m_ssl)), m_peer_cert(std::move(other.m_peer_cert)),
        m_should_shutdown(other.m_should_shutdown),
        m_pending_accept(std::move(other.m_pending_accept))
    {}

    TlsSocket::TlsSocket(Socket &&other, TlsContext ctx) :
        CppSockets::Socket(std::move(other)), // TODO: if socket is not connected, at that moment, does it break ?
        m_ctx(std::move(ctx)), m_ssl(SSL_ptr(SSL_new(m_ctx.get()))), m_peer_cert(nullptr)
    {
        init_ssl_socket(m_ssl.get(), this);
    }

    TlsSocket::TlsSocket(Socket &&other, SSL_ptr ssl) :
        CppSockets::Socket(std::move(other)), // TODO: if socket is not connected, at that moment, does it break ?
        m_ctx(ssl ? static_cast<const TlsContext&>(TlsContext(SSL_get_SSL_CTX(ssl.get()), false)) : SSL_CTX_new(TLS_method())),
        m_ssl(ssl ? std::move(ssl) : SSL_ptr(SSL_new(m_ctx.get()))),
        m_peer_cert(nullptr)
    {
        init_ssl_socket(m_ssl.get(), this);
    }

    TlsSocket::~TlsSocket() noexcept {
        try {
            this->close(true);
        } catch (const std::runtime_error& e) {
            std::cerr << "Failed to close TlsSocket: " << e.what() << '\n';
        }
    }

    auto TlsSocket::operator=(TlsSocket &&other) noexcept -> TlsSocket & {
        m_ssl = std::move(other.m_ssl);
        m_ctx = std::move(other.m_ctx);
        m_peer_cert = std::move(other.m_peer_cert);
        m_pending_accept = std::move(other.m_pending_accept);

        std::swap(m_should_shutdown, other.m_should_shutdown);

        Socket::operator=(std::move(other));
        return *this;
    }

    auto TlsSocket::close(bool force) -> bool {
        if (m_ssl && m_should_shutdown) {
            int ret = SSL_shutdown(m_ssl.get());

            if (ret < 0) {
                throw_tls_error("Failed to shutdown TLS: ", ret);
            } else if (ret == 1 || force) {
                Socket::close();
            } else { // ret == 0
                // TODO: wait for peer
                return false;
            }
        } else if (this->connected()) {
            Socket::close();
        }

        m_should_shutdown = false;
        m_peer_cert.reset();
        m_pending_accept.reset();

        if (m_ssl) {
            // Properly reset the SSL object so it can be reused by a subsequent
            // connect call to a different host
            this->set_hostname(nullptr);
            X509_VERIFY_PARAM_set1_ip(SSL_get0_param(m_ssl.get()), nullptr, 0);
            if (!SSL_clear(m_ssl.get()))
                throw std::runtime_error("Failed to reset SSL: " + openssl_extract_errors_from_stack());
        }
        return true;
    }

    void TlsSocket::set_verify_depth(int depth) {
        SSL_set_verify_depth(m_ssl.get(), depth);
    }

    void TlsSocket::set_hostname(const char *hostname) {
#if OPENSSL_VERSION_NUMBER >= 0x40000000L
        if (!SSL_set1_dnsname(m_ssl.get(), hostname)) {
#else
        if (!SSL_set1_host(m_ssl.get(), hostname)) {
#endif
            throw_tls_error("Failed to set hostname: ");
        }
    }

    void TlsSocket::set_certificate(const std::string &cert_path, const std::string &pkey_path) {
        BIO_ptr cert(BIO_new_file(cert_path.c_str(), "r"));
        BIO_ptr pkey(BIO_new_file(pkey_path.c_str(), "r"));
        // TODO: handle pkey password: SSL_set_default_passwd_cb or PEM_read_bio_X509 last 2 args
        X509_ptr x509(PEM_read_bio_X509(cert.get(), nullptr, nullptr, nullptr));
        EVP_PKEY_ptr evp_pkey(PEM_read_bio_PrivateKey(pkey.get(), nullptr, nullptr, nullptr));

        if (SSL_use_certificate(m_ssl.get(), x509.get()) <= 0) {
            throw_tls_error("Failed to set certificate: ");
        }

        if (SSL_use_PrivateKey(m_ssl.get(), evp_pkey.get()) <= 0 ) {
            throw_tls_error("Failed to set private key: ");
        }
    }

    auto TlsSocket::read(char *buff, std::size_t size) -> std::size_t {
        std::size_t nb = 0;
        int ret = SSL_read_ex(m_ssl.get(), buff, size, &nb);

        return handle_ssl_io_result("Failed to read from socket: ", ret, nb);
    }

    auto TlsSocket::has_more_data() const -> bool {
        if (SSL_pending(m_ssl.get()) > 0) {
            return true;
        }
        try {
            return static_cast<bool>(this->poll(PollEvent::READ));
        } catch (const std::runtime_error &) {
            // A poll error after at least one successful read must not discard
            // the data already read; stop draining and return it.
            return false;
        }
    }

    auto TlsSocket::write(const char *buff, std::size_t len) -> std::size_t {
        std::size_t nb = 0;
        int ret = SSL_write_ex(m_ssl.get(), static_cast<const void *>(buff), len, &nb);

        return handle_ssl_io_result("Failed to write to socket: ", ret, nb);
    }

    auto TlsSocket::handle_ssl_io_result(std::string error_msg, int ssl_ret, std::size_t nb) -> std::size_t {
        int shutdown = SSL_get_shutdown(m_ssl.get());

        if (shutdown == SSL_RECEIVED_SHUTDOWN) {
            SSL_shutdown(m_ssl.get()); // TODO: log failure
            m_should_shutdown = false;
        }

        if (ssl_ret > 0) {
            return nb;
        }

        int err = tls_errno(ssl_ret);

        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            return 0; // Non-blocking mode: caller must retry the operation later.
        }
        if (err == SSL_ERROR_ZERO_RETURN) {
            // Peer sent close_notify and closed the connection cleanly.
            SSL_shutdown(m_ssl.get()); // TODO: log failure
            m_should_shutdown = false;
            return 0;
        }
        throw_tls_error(std::move(error_msg), ssl_ret);
        return 0;
    }

    auto TlsSocket::connect(const IEndpoint &endpoint) -> int {
        // Drop the old session when reconnecting to a new endpoint
        if (SSL_is_init_finished(m_ssl.get())) {
            this->close(true);
        }

        if (!this->connected()) {
            Socket::connect(endpoint);
            if (!this->connected()) {
                return 0; // Non-blocking tcp still connecting
            }
        }

        // If we reconnected the TCP socket, we need to bind the new fd to SSL
        if (SSL_get_fd(m_ssl.get()) != this->get_fd()) {
            if (!SSL_set_fd(m_ssl.get(), this->get_fd())) {
                throw std::runtime_error(std::string("Failed to bind SSL to socket: ") + openssl_extract_errors_from_stack());
            }
        }

        int ssl_ret = SSL_connect(m_ssl.get());

        if (ssl_ret == 1) {
            m_should_shutdown = true;
            m_peer_cert.reset(SSL_get_peer_certificate(m_ssl.get()));
            return 1;
        }

        int err = tls_errno(ssl_ret);

        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            return 0; // Non-blocking handshake: need to poll() then call connect() again
        }
        throw_tls_error("Failed to connect: ", ssl_ret);
        return 0;
    }

    auto TlsSocket::accept(TlsContext ctx) -> std::unique_ptr<TlsSocket> {
        return std::unique_ptr<TlsSocket>(this->acceptImpl(nullptr, std::move(ctx)));
    }

    auto TlsSocket::accept(sockaddr_storage &addr_out, TlsContext ctx) -> std::unique_ptr<TlsSocket> {
        return std::unique_ptr<TlsSocket>(this->acceptImpl(&addr_out, std::move(ctx)));
    }

    auto TlsSocket::acceptImpl(sockaddr_storage *addr_out, TlsContext ctx) -> TlsSocket * {
        if (!m_pending_accept) {
            std::unique_ptr<Socket> res{Socket::acceptImpl(addr_out)};

            if (!res) {
                return nullptr;
            }
            m_pending_accept = std::make_unique<TlsSocket>(std::move(*res), std::move(ctx));
        }

        int ssl_ret = SSL_accept(m_pending_accept->get_ssl().get());

        if (ssl_ret == 1) {
            m_pending_accept->m_should_shutdown = true;
            m_pending_accept->m_peer_cert.reset(SSL_get_peer_certificate(m_pending_accept->get_ssl().get()));
            return m_pending_accept.release();
        }

        int err = m_pending_accept->tls_errno(ssl_ret);

        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            return nullptr; // Non-blocking handshake: need to poll() then call accept() again
        }
        m_pending_accept->throw_tls_error("Failed to accept TLS connection: ", ssl_ret);
        return nullptr;
    }

    auto TlsSocket::get_ssl_ctx() const -> TlsContext {
        return {SSL_get_SSL_CTX(m_ssl.get()), false};
    }

    auto TlsSocket::tls_errno(int ret) -> int {
        if (!m_ssl)
            throw std::runtime_error("SSL object is null");

        return SSL_get_error(m_ssl.get(), ret);
    }

    void TlsSocket::throw_tls_error(std::string message) {
        throw_tls_error(std::move(message), 0);
    }

    void TlsSocket::throw_tls_error(std::string message, int ret) {
        int err = tls_errno(ret);

        if (err == SSL_ERROR_SYSCALL || err == SSL_ERROR_SSL)
            m_should_shutdown = false;

        throw std::runtime_error(std::move(message) + ssl_strerror(err));
    }
}
