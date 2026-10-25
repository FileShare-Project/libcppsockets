/*
** Project LibCppSockets, 2025
**
** Author Francois Michaut
**
** Started on  Wed Aug 20 14:40:41 2025 Francois Michaut
** Last update Sun Oct 25 00:18:04 2026 Francois Michaut
**
** Context.cpp : Implementation of the Context for TLS sockets
*/

#include "CppSockets/Tls/Context.hpp"

#include "CppSockets/SslMacros.hpp"

#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <stdexcept>

#define TLS_CONTEXT_CONSTRUCTOR_BODY                                                                \
        REQUIRED_PTR(m_ptr, "SSL_CTX");                                                             \
        set_min_proto_version(TLS1_2_VERSION);

namespace CppSockets {
    TlsContext::TlsContext() :
        m_ptr(SSL_CTX_new(TLS_method()))
    {
        TLS_CONTEXT_CONSTRUCTOR_BODY;
    }

    TlsContext::TlsContext(SSL_CTX_ptr ptr) :
        m_ptr(std::move(ptr))
    {
        TLS_CONTEXT_CONSTRUCTOR_BODY;
    }

    TlsContext::TlsContext(SSL_CTX *ptr, bool own) :
        m_ptr(ptr), m_own(own)
    {
        TLS_CONTEXT_CONSTRUCTOR_BODY;
    }

    TlsContext::TlsContext(const TlsContext &other) {
        *this = other;
    }

    TlsContext::TlsContext(TlsContext &&other) noexcept {
        *this = std::move(other);
    }

    auto TlsContext::operator=(const TlsContext &other) -> TlsContext & {
        UP_REF_ASSIGNMENT_OPERATOR(SSL_CTX);
    }

    auto TlsContext::operator=(TlsContext &&other) noexcept -> TlsContext & {
        std::swap(m_ptr, other.m_ptr);
        std::swap(m_own, other.m_own);

        return *this;
    }

    MAKE_DESTRUCTOR(TlsContext)

    void TlsContext::set_min_proto_version(int version) {
        if (!SSL_CTX_set_min_proto_version(m_ptr.get(), version)) {
            throw std::runtime_error("Failed to set TlsProtocol Version");
        }
    }

    void TlsContext::set_verify_depth(int depth) {
        SSL_CTX_set_verify_depth(m_ptr.get(), depth);
    }

    void TlsContext::set_certificate(std::string_view cert_path, std::string_view pkey_path) {
        BIO_ptr cert(BIO_new_file(cert_path.data(), "r"));
        BIO_ptr pkey(BIO_new_file(pkey_path.data(), "r"));
        // TODO: handle pkey password: SSL_CTX_set_default_passwd_cb or PEM_read_bio_X509 last 2 args
        X509_ptr x509(PEM_read_bio_X509(cert.get(), nullptr, nullptr, nullptr));
        EVP_PKEY_ptr evp_pkey(PEM_read_bio_PrivateKey(pkey.get(), nullptr, nullptr, nullptr));

        if (SSL_CTX_use_certificate(m_ptr.get(), x509.get()) <= 0) {
            throw std::runtime_error("Failed to set certificate");
        }

        if (SSL_CTX_use_PrivateKey(m_ptr.get(), evp_pkey.get()) <= 0 ) {
            throw std::runtime_error("Failed to set private key");
        }
    }

    auto TlsContext::check_private_key() const -> bool {
       return SSL_CTX_check_private_key(m_ptr.get()) == 1;
    }
}
