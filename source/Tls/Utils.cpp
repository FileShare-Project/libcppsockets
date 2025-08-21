/*
** Project LibFileShareProtocol, 2025
**
** Author Francois Michaut
**
** Started on  Sun Aug  3 20:36:03 2025 Francois Michaut
** Last update Wed Aug 20 14:12:29 2025 Francois Michaut
**
** SSL_Utils.cpp : SSL Utility implementations
*/

#include "CppSockets/Tls/Utils.hpp"

#include <openssl/err.h>

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
        auto error = ERR_get_error();
        std::array<char, SSL_MAX_ERROR + 1> buff = {0};

        if (error == 0)
            return;

        ERR_error_string_n(error, buff.data(), buff.size());

        throw std::runtime_error(std::string(buff.data()));
    }

    auto check_or_throw_openssl_error(int ret) -> int {
        if (ret == 0) {
            throw_openssl_error();
        }
        return ret;
    }
}
