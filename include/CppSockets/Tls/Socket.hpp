/*
** Project LibCppSockets, 2022
**
** Author Francois Michaut
**
** Started on  Wed Sep 14 20:51:23 2022 Francois Michaut
** Last update Sun Oct 25 12:00:59 2026 Francois Michaut
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

            // read() with no length reads until the peer closes; use read(N) when reading from untrusted peers
            auto read(std::size_t len = -1) -> std::string override;
            auto read(char *buff, std::size_t size) -> std::size_t override;
            auto write(std::string_view buff) -> std::size_t override { return this->write(buff.data(), buff.size()); };
            auto write(const char *buff, std::size_t len) -> std::size_t override;

            void set_verify(int mode, TlsVerifyCallback verify_callback = nullptr);
            void set_verify_depth(int depth);
            void set_certificate(const std::string &cert_path, const std::string &pkey_path);
            auto connect(const IEndpoint &endpoint) -> int override;

            auto accept(void *addr_out, TlsContext ctx) -> std::unique_ptr<TlsSocket>;
            auto accept(void *addr_out = nullptr) -> std::unique_ptr<TlsSocket> { return accept(addr_out, m_ctx); }
            auto accept(TlsContext ctx) -> std::unique_ptr<TlsSocket> { return accept(nullptr, std::move(ctx)); }

            [[nodiscard]] auto get_ssl_ctx() const -> TlsContext;
            [[nodiscard]] auto get_ssl() const -> const SSL_ptr & { return m_ssl; }
            [[nodiscard]] auto get_peer_cert() const -> const X509_ptr & { return m_peer_cert; }

            [[nodiscard]] auto tls_strerror(int ret) -> std::string;
        protected:
            auto acceptImpl(void *addr_out) -> TlsSocket * override { return acceptImpl(addr_out, m_ctx); };
            auto acceptImpl(void *addr_out, TlsContext ctx) -> TlsSocket *;

            void throw_tls_error(std::string message);
            void throw_tls_error(std::string message, int ret);
        private:
            TlsContext m_ctx;
            SSL_ptr m_ssl;
            X509_ptr m_peer_cert;

            bool m_should_shutdown = false;
            void check_for_error(std::string error_msg, int ret);
    };
}
