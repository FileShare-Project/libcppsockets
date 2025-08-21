/*
** Project LibCppSockets, 2025
**
** Author Francois Michaut
**
** Started on  Fri Aug  1 09:54:53 2025 Francois Michaut
** Last update Wed Aug 20 16:49:57 2025 Francois Michaut
**
** Utils.hpp : Tls Utility types
*/

#pragma once

#include <openssl/ssl.h>

#include <functional>
#include <memory>

#define CPP_SOCKETS_TLS_UTILS_DEFINE_DTOR(TYPE, PREFIX)                        \
  struct TYPE##_dtor {                                                         \
    void operator()(TYPE *ptr) { PREFIX##_free(ptr); }                         \
  };

#define CPP_SOCKETS_TLS_UTILS_DEFINE_PTR_CMD_PREFIX(TYPE, PREFIX)              \
  CPP_SOCKETS_TLS_UTILS_DEFINE_DTOR(TYPE, PREFIX)                              \
  using TYPE##_ptr = std::unique_ptr<TYPE, TYPE##_dtor>;

#define CPP_SOCKETS_TLS_UTILS_DEFINE_PTR(TYPE)                                 \
  CPP_SOCKETS_TLS_UTILS_DEFINE_PTR_CMD_PREFIX(TYPE, TYPE)

namespace CppSockets {
    CPP_SOCKETS_TLS_UTILS_DEFINE_PTR(BIO)
    CPP_SOCKETS_TLS_UTILS_DEFINE_PTR_CMD_PREFIX(BIGNUM, BN)
    CPP_SOCKETS_TLS_UTILS_DEFINE_PTR(SSL_CTX)
    CPP_SOCKETS_TLS_UTILS_DEFINE_PTR(SSL)
    CPP_SOCKETS_TLS_UTILS_DEFINE_PTR(X509)
    CPP_SOCKETS_TLS_UTILS_DEFINE_PTR(X509_NAME)
    CPP_SOCKETS_TLS_UTILS_DEFINE_PTR(X509_NAME_ENTRY)
    CPP_SOCKETS_TLS_UTILS_DEFINE_PTR(X509_EXTENSION)
    CPP_SOCKETS_TLS_UTILS_DEFINE_PTR(ASN1_STRING)
    CPP_SOCKETS_TLS_UTILS_DEFINE_PTR(EVP_PKEY)
    CPP_SOCKETS_TLS_UTILS_DEFINE_PTR(EVP_MD)
    CPP_SOCKETS_TLS_UTILS_DEFINE_PTR(EVP_MD_CTX)

    void throw_openssl_error();
    auto check_or_throw_openssl_error(int ret) -> int;

    template<typename T>
    auto check_or_throw_openssl_error(T *ret) -> T * {
        if (ret == nullptr) {
            throw_openssl_error();
        }
        return ret;
    }

    using TlsVerifyCallback=std::function<int(int, X509_STORE_CTX *)>;
}

// Don't leak macros
#undef CPP_SOCKETS_TLS_UTILS_DEFINE_DTOR
#undef CPP_SOCKETS_TLS_UTILS_DEFINE_PTR
