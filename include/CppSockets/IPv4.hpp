/*
** Project CppSockets, 2022
**
** Author Francois Michaut
**
** Started on  Sun Feb 13 17:05:02 2022 Francois Michaut
** Last update Wed Aug 20 12:57:35 2025 Francois Michaut
**
** IPv4.hpp : Class used to represent and manipulate IPv4 addresses
*/

#pragma once

#include "CppSockets/Address.hpp"

namespace CppSockets {
    class IPv4 : public IAddress {
        public:
            explicit IPv4(std::uint32_t addr);
            IPv4(const char *addr); // TODO add support for string. Maybe string_view ?

            [[nodiscard]] auto get_address() const -> std::uint32_t override;
            [[nodiscard]] auto get_family() const -> int override;
            [[nodiscard]] auto to_string() const -> const std::string & override;

        private:
            std::uint32_t addr;
            std::string str;
    };
    using EndpointV4 = Endpoint<IPv4>;
}
