/*
** Project LibCppSockets, 2025
**
** Author Francois Michaut
**
** Started on  Fri Aug  1 09:54:53 2025 Francois Michaut
** Last update Sun Aug  3 23:32:20 2025 Francois Michaut
**
** SSL_Utils.hpp : SSL Utility types
*/

#pragma once

#include <openssl/ssl.h>

#include <memory>

#define CPP_SOCKETS_SSL_UTILS_DEFINE_DTOR(TYPE)                                \
  struct TYPE##_dtor {                                                         \
    void operator()(TYPE *ptr) { TYPE##_free(ptr); }                           \
  };

#define CPP_SOCKETS_SSL_UTILS_DEFINE_PTR(TYPE)                                 \
  CPP_SOCKETS_SSL_UTILS_DEFINE_DTOR(TYPE)                                      \
  using TYPE##_ptr = std::unique_ptr<TYPE, TYPE##_dtor>;

namespace CppSockets {
    CPP_SOCKETS_SSL_UTILS_DEFINE_PTR(BIO)
    CPP_SOCKETS_SSL_UTILS_DEFINE_PTR(SSL_CTX)
    CPP_SOCKETS_SSL_UTILS_DEFINE_PTR(SSL)
    CPP_SOCKETS_SSL_UTILS_DEFINE_PTR(X509)
    CPP_SOCKETS_SSL_UTILS_DEFINE_PTR(X509_NAME)
    CPP_SOCKETS_SSL_UTILS_DEFINE_PTR(X509_NAME_ENTRY)
    CPP_SOCKETS_SSL_UTILS_DEFINE_PTR(X509_EXTENSION)
    CPP_SOCKETS_SSL_UTILS_DEFINE_PTR(EVP_PKEY)
    CPP_SOCKETS_SSL_UTILS_DEFINE_PTR(EVP_MD)
    CPP_SOCKETS_SSL_UTILS_DEFINE_PTR(EVP_MD_CTX)

    void throw_openssl_error();
    auto check_or_throw_openssl_error(int ret) -> int;

    template<typename T>
    auto check_or_throw_openssl_error(T *ret) -> T * {
        if (ret == nullptr) {
            throw_openssl_error();
        }
        return ret;
    }
}

// Don't leak macros
#undef CPP_SOCKETS_SSL_UTILS_DEFINE_DTOR
#undef CPP_SOCKETS_SSL_UTILS_DEFINE_PTR
