/*
** Project LibCppSockets, 2022
**
** Author Francois Michaut
**
** Started on  Wed Sep 14 20:51:23 2022 Francois Michaut
** Last update Mon Oct 26 21:37:23 2026 Francois Michaut
**
** SecureSocket.hpp : TLS socket wrapper using openssl
*/

#pragma once

#include "CppSockets/OSDetection.hpp"
#include "CppSockets/Socket.hpp"
#include "CppSockets/Tls/Context.hpp"
#include "CppSockets/Tls/Utils.hpp"

namespace CppSockets {
    // TODO add more TLS-related functions
    class TlsSocket : public Socket {
        public:
            TlsSocket() = default; // TODO: Null-init m_ssl, would segfault on any function call. Find a safer way.
            TlsSocket(int domain, int type, int protocol, TlsContext ctx = {});
            explicit TlsSocket(Socket &&other, TlsContext ctx = {});
            explicit TlsSocket(Socket &&other, SSL_ptr ssl = nullptr);
            explicit TlsSocket(RawSocketType fd, SSL_ptr ssl = nullptr);
            ~TlsSocket() noexcept override;

            TlsSocket(const TlsSocket &other) = delete;
            TlsSocket(TlsSocket &&other) noexcept;
            auto operator=(const TlsSocket &other) -> TlsSocket & = delete;
            auto operator=(TlsSocket &&other) noexcept -> TlsSocket &;

            void close() override { this->close(false); };
            bool close(bool force);

            // TODO: Add support for SSL_sendfile + SNI / ALPN
            auto read(char *buff, std::size_t size) -> std::size_t override;
            auto write(const char *buff, std::size_t len) -> std::size_t override;

            void set_verify(int mode, TlsVerifyCallback verify_callback = nullptr);
            void set_verify_depth(int depth);
            void set_certificate(const std::string &cert_path, const std::string &pkey_path);
            // Must be called before connect() for hostname verification to take
            // effect (requires peer verification to be enabled).
            void set_hostname(const std::string &hostname) { set_hostname(hostname.c_str()); }
            void set_hostname(const char *hostname);

            // TODO: Add connect overload that take a string hostname and port and call set_hostname automatically
            auto connect(const IEndpoint &endpoint) -> int override;

            auto accept() -> std::unique_ptr<TlsSocket> { return accept(m_ctx); }
            auto accept(TlsContext ctx) -> std::unique_ptr<TlsSocket>;
            auto accept(sockaddr_storage &addr) -> std::unique_ptr<TlsSocket> { return accept(addr, m_ctx); }
            auto accept(sockaddr_storage &addr, TlsContext ctx) -> std::unique_ptr<TlsSocket>;

            [[nodiscard]] auto get_ssl_ctx() const -> TlsContext;
            [[nodiscard]] auto get_ssl() const -> const SSL_ptr & { return m_ssl; }
            [[nodiscard]] auto get_peer_cert() const -> const X509_ptr & { return m_peer_cert; }

            [[nodiscard]] auto tls_errno(int ret) -> int;
        protected:
            auto acceptImpl(sockaddr_storage *addr_out) -> TlsSocket * override { return acceptImpl(addr_out, m_ctx); };
            auto acceptImpl(sockaddr_storage *addr_out, TlsContext ctx) -> TlsSocket *;

            [[nodiscard]] auto has_more_data() const -> bool override;

            void throw_tls_error(std::string message);
            void throw_tls_error(std::string message, int ret);
        private:
            TlsContext m_ctx;
            SSL_ptr m_ssl;
            X509_ptr m_peer_cert;

            bool m_should_shutdown = false;
            std::unique_ptr<TlsSocket> m_pending_accept; // partially handshaken accepted socket, for non-blocking sockets
            auto handle_ssl_io_result(std::string error_msg, int ssl_ret, std::size_t nb) -> std::size_t;
    };
}
