/*
** Project LibCppSockets, 2022
**
** Author Francois Michaut
**
** Started on  Thu Sep 15 14:24:25 2022 Francois Michaut
** Last update Tue May  9 23:34:46 2023 Francois Michaut
**
** init.cpp : Startup/Cleanup functions implementation
*/

#include "CppSockets/OSDetection.hpp"
#include "CppSockets/SocketInit.hpp"

#include <stdexcept>
#include <string>

#ifdef OS_WINDOWS
  #include <winsock2.h>
  #include <openssl/applink.c>
#else
  #include <openssl/err.h>
  #include <openssl/ssl.h>
#endif

namespace CppSockets {
    static bool init() {
#ifdef OS_WINDOWS
        WSADATA wsa_data;

        // TODO check value in wsa_data
        if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
            // TODO: use WSAGetLastError
            throw std::runtime_error(std::string("WASStartup Failed : ") + std::strerror(errno));
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
            throw std::runtime_error(std::string("WSACleanup Failed : ") + std::to_string(WSAGetLastError()));
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

    bool SocketInit::init = CppSockets::init();
    SocketInit::Cleanup SocketInit::cleanup;
}
