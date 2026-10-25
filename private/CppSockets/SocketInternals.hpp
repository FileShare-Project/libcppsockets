/*
** Project LibCppSockets, 2022
**
** Author Francois Michaut
**
** Started on  Mon Oct 26 11:05:41 2026 Francois Michaut
** Last update Mon Oct 26 21:41:31 2026 Francois Michaut
**
** SocketInternals.hpp : Private constants shared by Socket implementations
*/

#pragma once

#include "CppSockets/OSDetection.hpp"

#include <cstddef>

#ifdef OS_WINDOWS
  #include <winsock2.h>
#else
  #include <cerrno>
#endif

namespace CppSockets {
    static constexpr std::size_t BUFF_SIZE = 4096;

    // Normalized socket error codes. get_errno() returns WSAGetLastError()
    // on Windows and errno for linux. Using unified constants simplifies portable logic.
#ifdef OS_WINDOWS
    static constexpr int SOCK_EINTR        = WSAEINTR;
    static constexpr int SOCK_EAGAIN       = WSAEWOULDBLOCK; // Winsock has no EAGAIN
    static constexpr int SOCK_EWOULDBLOCK  = WSAEWOULDBLOCK;
    static constexpr int SOCK_EINPROGRESS  = WSAEINPROGRESS;
    static constexpr int SOCK_EALREADY     = WSAEALREADY;
    static constexpr int SOCK_EISCONN      = WSAEISCONN;
#else
    static constexpr int SOCK_EINTR        = EINTR;
    static constexpr int SOCK_EAGAIN       = EAGAIN;
    static constexpr int SOCK_EWOULDBLOCK  = EWOULDBLOCK;
    static constexpr int SOCK_EINPROGRESS  = EINPROGRESS;
    static constexpr int SOCK_EALREADY     = EALREADY;
    static constexpr int SOCK_EISCONN      = EISCONN;
#endif
}
