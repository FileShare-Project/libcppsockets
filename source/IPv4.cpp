/*
** Project CppSocket, 2022
**
** Author Francois Michaut
**
** Started on  Sun Feb 13 18:52:28 2022 Francois Michaut
** Last update Sat Dec  2 16:17:43 2023 Francois Michaut
**
** IPv4.cpp : Implementation of IPv4 class
*/

#include "CppSockets/IPv4.hpp"
#include "CppSockets/Socket.hpp"

#include <array>
#include <stdexcept>

#ifdef OS_WINDOWS
  #include <ws2tcpip.h>
#else
  #include <arpa/inet.h>
#endif

namespace CppSockets {
    IPv4::IPv4(std::uint32_t addr) :
        addr(htonl(addr))
    {
        std::array<char, 17> buff = {0};

        inet_ntop(AF_INET, &this->addr, buff.data(), buff.size());
        str = buff.data();
    }

    IPv4::IPv4(const char *addr) :
        str(addr)
    {
        struct in_addr in;

        if (inet_pton(AF_INET, addr, &in) != 1)
            throw std::runtime_error("Invalid IPv4 address");
        this->addr = in.s_addr;
    }

    std::uint32_t IPv4::getAddress() const {
        return addr;
    }

    const std::string &IPv4::toString() const {
        return str;
    }

    int IPv4::getFamily() const {
        return AF_INET;
    }
}
