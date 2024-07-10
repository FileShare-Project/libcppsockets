/*
** Project LibCppSockets, 2022
**
** Author Francois Michaut
**
** Started on  Wed Sep 14 20:51:23 2022 Francois Michaut
** Last update Tue Nov 14 19:37:45 2023 Francois Michaut
**
** SecureSocket.hpp : TLS socket wrapper using openssl
*/

#pragma once

#include "CppSockets/OSDetection.hpp"

#include "CppSockets/IPv4.hpp"
#include "CppSockets/Socket.hpp"

#include <functional>

// TODO: find a better way do to this
using BIO = struct bio_st;
using SSL = struct ssl_st;
using SSL_METHOD = struct ssl_method_st;
using SSL_CTX = struct ssl_ctx_st;
using X509 = struct x509_st;
using RSA = struct rsa_st;
using EVP_PKEY = struct evp_pkey_st;
using EVP_MD = struct evp_md_st;
using EVP_MD_CTX = struct evp_md_ctx_st;

namespace CppSockets {
    using BIO_ptr=std::unique_ptr<BIO, std::function<void(BIO *)>>;
    using SSL_CTX_ptr=std::unique_ptr<SSL_CTX, std::function<void(SSL_CTX *)>>;
    using SSL_ptr=std::unique_ptr<SSL, std::function<void(SSL *)>>;
    using X509_ptr=std::unique_ptr<X509, std::function<void(X509 *)>>;
    using RSA_ptr=std::unique_ptr<RSA, std::function<void(RSA *)>>;
    using EVP_PKEY_ptr=std::unique_ptr<EVP_PKEY, std::function<void(EVP_PKEY *)>>;
    using EVP_MD_ptr=std::unique_ptr<EVP_MD, std::function<void(EVP_MD *)>>;
    using EVP_MD_CTX_ptr=std::unique_ptr<EVP_MD_CTX, std::function<void(EVP_MD_CTX *)>>;

    // TODO add more TLS-related functions
    class TlsSocket : public Socket {
        public:
            TlsSocket() = default;
            TlsSocket(int domain, int type, int protocol);
            TlsSocket(Socket &&other, SSL_ptr ssl = nullptr);
            TlsSocket(RawSocketType fd, SSL_ptr ssl = nullptr);
            ~TlsSocket();

            TlsSocket(const TlsSocket &other) = delete;
            TlsSocket(TlsSocket &&other) noexcept;
            TlsSocket &operator=(const TlsSocket &other) = delete;
            TlsSocket &operator=(TlsSocket &&other) noexcept;

            std::string read(std::size_t len = -1);
            std::size_t read(char *buff, std::size_t size);
            std::size_t write(const std::string &buff);
            std::size_t write(std::string_view buff);
            std::size_t write(const char *buff, std::size_t len);

            void set_certificate(std::string cert_path, std::string pkey_path);
            int connect(const IEndpoint &endpoint);

            std::shared_ptr<TlsSocket> accept(void *addr_out = nullptr);

            [[nodiscard]]
            const SSL_CTX_ptr &get_ssl_ctx() const;
            [[nodiscard]]
            const SSL_ptr &get_ssl() const;
            [[nodiscard]]
            const X509_ptr &get_client_cert() const;

            [[nodiscard]]
            const std::string tls_strerror(int ret);
        private:
            SSL_CTX_ptr m_ctx;
            SSL_ptr m_ssl;
            X509_ptr m_peer_cert;
            X509_ptr m_cert;
            EVP_PKEY_ptr m_pkey;

            void check_for_error(std::string error_msg, int ret);
    };

    inline std::size_t TlsSocket::write(std::string_view buff) {
        return write(buff.data(), buff.size());
    }

    inline std::size_t TlsSocket::write(const std::string &buff) {
        return write(buff.c_str(), buff.size());
    }

    inline const SSL_CTX_ptr &TlsSocket::get_ssl_ctx() const {
        return m_ctx;
    }

    inline const SSL_ptr &TlsSocket::get_ssl() const {
        return m_ssl;
    }

    inline const X509_ptr &TlsSocket::get_client_cert() const {
        return m_peer_cert;
    }
}
