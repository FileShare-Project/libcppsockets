/*
** Project CppSocket, 2022
**
** Author Francois Michaut
**
** Started on  Sun Feb 13 18:52:28 2022 Francois Michaut
** Last update Thu Jul 20 23:08:49 2023 Francois Michaut
**
** IPv4.cpp : Implementation of IPv4 class
*/

#include "CppSockets/IPv4.hpp"
#include "CppSockets/Socket.hpp"

#include <stdexcept>

#include <arpa/inet.h>

namespace CppSockets {
    IPv4::IPv4(std::uint32_t addr) :
        addr(htonl(addr))
    {
        struct in_addr tmp {this->addr};

        str = inet_ntoa(tmp);
    }

    IPv4::IPv4(const char *addr) :
        str(addr)
    {
        struct in_addr in;

        if (inet_aton(addr, &in) == 0)
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
