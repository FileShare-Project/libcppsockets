/*
** Project LibCppSockets, 2025
**
** Author Francois Michaut
**
** Started on  Wed Aug 20 14:40:41 2025 Francois Michaut
** Last update Fri Aug 22 21:46:12 2025 Francois Michaut
**
** Context.cpp : Implementation of the Context for TLS sockets
*/

#include "CppSockets/Tls/Context.hpp"

#include "CppSockets/SslMacros.hpp"

#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/crypto.h>

#include <stdexcept>

namespace CppSockets {
    // TODO: Free this ?
    const int TLS_CONTEXT_IDX = SSL_CTX_get_ex_new_index(0, (void *)"TlsContent index", nullptr, nullptr, nullptr);

    struct TlsContext_Accessor {
        static auto get_function(TlsContext &ctx) -> TlsVerifyCallback & {
            return ctx.m_verify_callback;
        }
    };

    static auto tls_context_verify_callback(int preverify_ok, X509_STORE_CTX *ctx) -> int {
        SSL *ssl = static_cast<SSL *>(X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx()));
        SSL_CTX *ssl_ctx = SSL_get_SSL_CTX(ssl);

        auto *tls_ctx = static_cast<CppSockets::TlsContext *>(SSL_CTX_get_ex_data(ssl_ctx, TLS_CONTEXT_IDX));

        return CppSockets::TlsContext_Accessor::get_function(*tls_ctx)(preverify_ok, ctx);
    }
}

#define TLS_CONTEXT_CONSTRUCTOR_BODY                                                                \
        REQUIRED_PTR(m_ptr, "SSL_CTX");                                                             \
        SSL_CTX_set_ex_data(m_ptr.get(), TLS_CONTEXT_IDX, this);                                    \
        set_min_proto_version(TLS1_1_VERSION);

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

    TlsContext::TlsContext(TlsContext &&other) noexcept {
        *this = other;
    }

    auto TlsContext::operator=(const TlsContext &other) -> TlsContext & {
        UP_REF_ASSIGNMENT_OPERATOR(SSL_CTX)
    }

    auto TlsContext::operator=(TlsContext &&other) noexcept -> TlsContext & {
        std::swap(m_ptr, other.m_ptr);
        std::swap(m_own, other.m_own);

        m_verify_callback = std::move(other.m_verify_callback);
        return *this;
    }

    MAKE_DESTRUCTOR(TlsContext)

    void TlsContext::set_min_proto_version(int version) {
        if (!SSL_CTX_set_min_proto_version(m_ptr.get(), version)) {
            throw std::runtime_error("Failed to set TlsProtocol Version");
        }
    }

    void TlsContext::set_verify(int mode, TlsVerifyCallback callback) {
        if (!m_own) {
            // We would loose the TlsVerifyCallback if the TlsContext goes out of scope, but the SSL_CTX
            // hasn't been freed yet, which would result in a crash if the callback was then requested
            throw std::runtime_error("Can't set_verify on a non-owned TlsContext. Use the Raw SSL_CTX methods");
        }
        m_verify_callback = std::move(callback);
        SSL_verify_cb raw_cb = m_verify_callback ? tls_context_verify_callback : nullptr;

        SSL_CTX_set_verify(m_ptr.get(), mode, raw_cb);
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
