/*
** Project LibCppSockets, 2022
**
** Author Francois Michaut
**
** Started on  Sun Feb 13 17:05:02 2022 Francois Michaut
** Last update Mon Oct 26 14:26:38 2026 Francois Michaut
**
** IPv4.hpp : Class used to represent and manipulate IPv4 addresses
*/

#pragma once

#include "CppSockets/Address.hpp"

#include <string_view>

namespace CppSockets {
    class IPv4 : public IAddress {
        public:
            IPv4(std::string_view addr);

            static auto from_host_order(std::uint32_t addr) -> IPv4;
            static auto from_network_order(std::uint32_t addr) -> IPv4;

            // returns address in network byte order
            [[nodiscard]] auto get_address() const -> std::uint32_t override;
            [[nodiscard]] auto get_family() const -> int override;
            [[nodiscard]] auto to_string() const -> const std::string & override;

        private:
            IPv4(std::uint32_t addr);

            std::uint32_t addr; // always network byte order
            std::string str;
    };
    using EndpointV4 = Endpoint<IPv4>;
}
