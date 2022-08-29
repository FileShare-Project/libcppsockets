/*
** Project CppSocket, 2022
**
** Author Francois Michaut
**
** Started on  Sun Feb 13 18:52:28 2022 Francois Michaut
** Last update Mon Aug 29 20:45:54 2022 Francois Michaut
**
** IPv4.cpp : Implementation of IPv4 class
*/

#include "CppSockets/IPv4.hpp"
#include "CppSockets/Socket.hpp"

#include <arpa/inet.h>

namespace CppSockets {
    IPv4::IPv4(std::uint32_t addr) :
        addr(htonl(addr))
    {
        struct in_addr tmp {this->addr};

        str = inet_ntoa(tmp);
    }

    IPv4::IPv4(const char *addr) :
        addr(inet_addr(addr))
    {}

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
