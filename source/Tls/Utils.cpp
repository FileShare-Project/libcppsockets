/*
** Project LibCppSockets, 2025
**
** Author Francois Michaut
**
** Started on  Sun Aug  3 20:36:03 2025 Francois Michaut
** Last update Mon Oct 26 00:17:24 2026 Francois Michaut
**
** SSL_Utils.cpp : SSL Utility implementations
*/

#include "CppSockets/ErrorUtils.hpp"
#include "CppSockets/Tls/Utils.hpp"

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <array>
#include <stdexcept>
#include <string>

const auto SSL_MAX_ERROR = 256;

namespace CppSockets {
    // TODO: Double check the usage of theses functions :
    // - Is there any place where they are used, where the function called doesn't push an error for ERR_get_error
    // - Is there any place where they should be used, but we are throwing a manual exception ?

    // TODO: Use a custom exception instead of runtime error
    void throw_openssl_error() {
        std::string errors = openssl_extract_errors_from_stack();

        if (errors.empty()) {
            return;
        }

        throw std::runtime_error(errors);
    }

    auto openssl_extract_errors_from_stack() -> std::string {
        auto error = ERR_get_error();
        std::array<char, SSL_MAX_ERROR + 1> buff = {0};
        std::string errors;

        while (error != 0) {
            ERR_error_string_n(error, buff.data(), buff.size());
            errors.append(buff.data());
            error = ERR_get_error();
            if (error != 0) {
                errors += '\n';
            }
        }
        return errors;
    }

    auto check_or_throw_openssl_error(int ret) -> int {
        if (ret == 0) {
            throw_openssl_error();
        }
        return ret;
    }

    auto ssl_strerror(int err) -> std::string {
        switch (err) {
            case SSL_ERROR_NONE:
                return "No error";
            case SSL_ERROR_ZERO_RETURN:
                return "Peer closed TLS connection";
            case SSL_ERROR_WANT_READ:
                return "Retry the operation later: WANT_READ";
            case SSL_ERROR_WANT_WRITE:
                return "Retry the operation later: WANT_WRITE";
            case SSL_ERROR_WANT_CONNECT:
                return "Retry the operation later: WANT_CONNECT";
            case SSL_ERROR_WANT_ACCEPT:
                return "Retry the operation later: WANT_ACCEPT";
            case SSL_ERROR_WANT_X509_LOOKUP:
                return "Retry the operation later: WANT_X509_LOOKUP";
            case SSL_ERROR_WANT_ASYNC:
                return "Retry the operation later: WANT_ASYNC";
            case SSL_ERROR_WANT_ASYNC_JOB:
                return "Retry the operation later: WANT_ASYNC_JOB";
            case SSL_ERROR_WANT_CLIENT_HELLO_CB:
                return "Retry the operation later: WANT_CLIENT_HELLO_CB";
            case SSL_ERROR_SYSCALL:
                return std::string("Fatal system error: ") + CppSockets::strerror() + '\n' + openssl_extract_errors_from_stack();
            case SSL_ERROR_SSL:
                return  "Fatal TLS error: " + openssl_extract_errors_from_stack();
            default:
                return "Unknown error: " + std::to_string(err) + '\n' + openssl_extract_errors_from_stack();
        }
    }
}
