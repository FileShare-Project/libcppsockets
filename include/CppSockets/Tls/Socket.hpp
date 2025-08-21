/*
** Project LibCppSockets, 2022
**
** Author Francois Michaut
**
** Started on  Wed Sep 14 20:51:23 2022 Francois Michaut
** Last update Wed Aug 20 23:11:28 2025 Francois Michaut
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
            TlsSocket() = default;
            // TODO: Constructor allowing application to reuse SSL_CTX objects
            // (Maybe even a different TLS_CTX class to manage them ?)
            TlsSocket(int domain, int type, int protocol, TlsContext ctx = {});
            explicit TlsSocket(Socket &&other, TlsContext ctx = {});
            explicit TlsSocket(Socket &&other, SSL_ptr ssl = nullptr);
            explicit TlsSocket(RawSocketType fd, SSL_ptr ssl = nullptr);
            ~TlsSocket() noexcept;

            TlsSocket(const TlsSocket &other) = delete;
            TlsSocket(TlsSocket &&other) noexcept;
            auto operator=(const TlsSocket &other) -> TlsSocket & = delete;
            auto operator=(TlsSocket &&other) noexcept -> TlsSocket &;

            auto read(std::size_t len = -1) -> std::string;
            auto read(char *buff, std::size_t size) -> std::size_t;
            auto write(std::string_view buff) -> std::size_t { return this->write(buff.data(), buff.size()); };
            auto write(const char *buff, std::size_t len) -> std::size_t;

            void set_verify(int mode, SSL_verify_cb verify_callback = nullptr);
            void set_certificate(const std::string &cert_path, const std::string &pkey_path);
            auto connect(const IEndpoint &endpoint) -> int;

            auto accept(void *addr_out, TlsContext ctx) -> std::unique_ptr<TlsSocket>;
            auto accept(void *addr_out = nullptr) -> std::unique_ptr<TlsSocket> { return accept(addr_out, m_ctx); }
            auto accept(TlsContext ctx) -> std::unique_ptr<TlsSocket> { return accept(nullptr, std::move(ctx)); }

            [[nodiscard]] auto get_ssl_ctx() const -> TlsContext;
            [[nodiscard]] auto get_ssl() const -> const SSL_ptr & { return m_ssl; }
            [[nodiscard]] auto get_peer_cert() const -> const X509_ptr & { return m_peer_cert; }

            [[nodiscard]] auto tls_strerror(int ret) -> std::string;
        private:
            TlsContext m_ctx;
            SSL_ptr m_ssl;
            X509_ptr m_peer_cert;

            void check_for_error(const std::string &error_msg, int ret);
    };
}
