/*
** Project LibCppSockets, 2022
**
** Author Francois Michaut
**
** Started on  Thu Sep 15 14:24:25 2022 Francois Michaut
** Last update Mon Aug 10 22:38:13 2026 Francois Michaut
**
** init.cpp : Startup/Cleanup functions implementation
*/

#include "CppSockets/OSDetection.hpp"
#include "CppSockets/internal/SocketInit.hpp"

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <stdexcept>
#include <string>

#ifdef OS_WINDOWS
  #include <cstring>
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
        if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
            // TODO: use WSAGetLastError
            init_error = std::string("WASStartup Failed : ") + std::strerror(errno);
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
            // TODO use FormatMessage to get the error string
            std::cerr << std::string("WSACleanup Failed : ") << std::to_string(WSAGetLastError()) << '\n';
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
