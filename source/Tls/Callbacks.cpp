/*
** Project LibCppSockets, 2026
**
** Author Francois Michaut
**
** Started on  Sat Oct 24 23:24:43 2026 Francois Michaut
** Last update Sun Oct 25 12:15:48 2026 Francois Michaut
**
** Callbacks.cpp : Centralization of the boilerplate for verify callbacks
*/

#include "CppSockets/Tls/Context.hpp"
#include "CppSockets/Tls/Socket.hpp"

namespace {
    struct TlsCallbackData {
        CppSockets::TlsVerifyCallback callback;
    };

    void tls_context_ex_data_free(void *_parent, void *ptr, CRYPTO_EX_DATA *_ad, int _idx, long _argl, void *_argp) {
        delete static_cast<TlsCallbackData *>(ptr);
    }

    // TODO: Free this ?
    // NOLINTNEXTLINE(cert-err58-cpp)
    const int TLS_CONTEXT_CALLBACK_STRUCT_IDX = SSL_CTX_get_ex_new_index(0, (void *)"TlsContext callback struct index", nullptr, nullptr, tls_context_ex_data_free);
    // NOLINTNEXTLINE(cert-err58-cpp)
    const int TLS_SOCKET_CALLBACK_STRUCT_IDX = SSL_get_ex_new_index(0, (void *)"TlsSocket callback struct index", nullptr, nullptr, tls_context_ex_data_free);

    auto tls_context_verify_callback(int preverify_ok, X509_STORE_CTX *ctx) -> int {
        SSL *ssl = static_cast<SSL *>(X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx()));
        SSL_CTX *ssl_ctx = SSL_get_SSL_CTX(ssl);

        auto *data = static_cast<TlsCallbackData *>(SSL_CTX_get_ex_data(ssl_ctx, TLS_CONTEXT_CALLBACK_STRUCT_IDX));
        return data->callback(preverify_ok, ctx);
    }

    auto ssl_verify_callback(int preverify_ok, X509_STORE_CTX *ctx) -> int {
        SSL *ssl = static_cast<SSL *>(X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx()));

        auto *data = static_cast<TlsCallbackData *>(SSL_get_ex_data(ssl, TLS_SOCKET_CALLBACK_STRUCT_IDX));
        return data->callback(preverify_ok, ctx);
    }
}

namespace CppSockets {
    void TlsContext::set_verify(int mode, TlsVerifyCallback callback) {
        void *previous = SSL_CTX_get_ex_data(m_ptr.get(), TLS_CONTEXT_CALLBACK_STRUCT_IDX);

        delete static_cast<TlsCallbackData *>(previous);
        if (callback) {
            auto *cb_data = new TlsCallbackData{std::move(callback)};

            SSL_CTX_set_ex_data(m_ptr.get(), TLS_CONTEXT_CALLBACK_STRUCT_IDX, cb_data);
            SSL_CTX_set_verify(m_ptr.get(), mode, tls_context_verify_callback);
        } else {
            SSL_CTX_set_verify(m_ptr.get(), mode, nullptr);
        }
    }

    void TlsSocket::set_verify(int mode, TlsVerifyCallback callback) {
        void *previous = SSL_get_ex_data(m_ssl.get(), TLS_SOCKET_CALLBACK_STRUCT_IDX);

        delete static_cast<TlsCallbackData *>(previous);
        if (callback) {
            auto *cb_data = new TlsCallbackData{std::move(callback)};

            SSL_set_ex_data(m_ssl.get(), TLS_SOCKET_CALLBACK_STRUCT_IDX, cb_data);
            SSL_set_verify(m_ssl.get(), mode, ssl_verify_callback);
        } else {
            SSL_set_verify(m_ssl.get(), mode, nullptr);
        }
    }
}
