/*
** Project LibCppSockets, 2022
**
** Author Francois Michaut
**
** Started on  Sun Feb 13 18:52:28 2022 Francois Michaut
** Last update Mon Oct 26 14:27:02 2026 Francois Michaut
**
** IPv4.cpp : Implementation of IPv4 class
*/

#include "CppSockets/OSDetection.hpp"
#include "CppSockets/IPv4.hpp"

#include <array>
#include <stdexcept>

#ifdef OS_WINDOWS
  #include <ws2tcpip.h>
#else
  #include <arpa/inet.h>
#endif

constexpr std::uint8_t MAX_ADDR_SIZE = 16;

namespace CppSockets {
    IPv4::IPv4(std::uint32_t addr) :
        addr(addr)
    {
        std::array<char, MAX_ADDR_SIZE + 1> buff = {0};

        inet_ntop(AF_INET, &this->addr, buff.data(), buff.size());
        str = buff.data();
    }

    auto IPv4::from_host_order(std::uint32_t addr) -> IPv4 {
        return IPv4(htonl(addr));
    }

    auto IPv4::from_network_order(std::uint32_t addr) -> IPv4 {
        return IPv4(addr);
    }

    IPv4::IPv4(std::string_view addr) :
        str(addr)
    {
        struct in_addr address = {};

        if (inet_pton(AF_INET, str.c_str(), &address) != 1)
            throw std::runtime_error("Invalid IPv4 address");
        this->addr = address.s_addr;
    }

    auto IPv4::get_address() const -> std::uint32_t {
        return addr;
    }

    auto IPv4::to_string() const -> const std::string & {
        return str;
    }

    auto IPv4::get_family() const -> int {
        return AF_INET;
    }
}
