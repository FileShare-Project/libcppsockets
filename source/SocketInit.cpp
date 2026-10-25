/*
** Project LibCppSockets, 2022
**
** Author Francois Michaut
**
** Started on  Thu Sep 15 14:24:25 2022 Francois Michaut
** Last update Mon Oct 26 22:48:19 2026 Francois Michaut
**
** init.cpp : Startup/Cleanup functions implementation
*/

#include "CppSockets/ErrorUtils.hpp"
#include "CppSockets/OSDetection.hpp"
#include "CppSockets/internal/SocketInit.hpp"

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <stdexcept>
#include <string>

#ifdef OS_WINDOWS
  #include <iostream>

  #include <winsock2.h>
  #include <openssl/applink.c>
#endif

static std::string init_error;

namespace CppSockets {
    static auto init() noexcept -> bool {
#ifdef OS_WINDOWS
        WSADATA wsa_data;

        // TODO check value in wsa_data
        const int wsa_error = WSAStartup(MAKEWORD(2, 2), &wsa_data);
        if (wsa_error != 0) {
            init_error = std::string("WSAStartup Failed : ") + CppSockets::strerror(wsa_error);
            std::cerr << init_error << '\n';
            return false;
        }
#else
        // TODO check if all of this is needed (commented out because it should not)
        // TODO check return values / raise errors
        // SSL_load_error_strings();
        // SSL_library_init();
        // OpenSSL_add_all_algorithms();
#endif
        return true;
    }

    static void deinit() {
#ifdef OS_WINDOWS
        if (WSACleanup() == SOCKET_ERROR) {
            std::cerr << std::string("WSACleanup Failed : ") << CppSockets::strerror() << '\n';
        }
#else
        // TODO check return values / raise errors
        // ERR_free_strings();
        // EVP_cleanup();
#endif
    }

    SocketInit::Cleanup::~Cleanup() {
        deinit();
    }

    const bool SocketInit::init = CppSockets::init();
    const SocketInit::Cleanup SocketInit::cleanup;

    SocketInit::SocketInit() {
        if (!init) [[unlikely]] {
            throw std::runtime_error(init_error);
        }
    }
}
