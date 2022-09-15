/*
** Project CppSockets, 2022
**
** Author Francois Michaut
**
** Started on  Sun Feb 13 17:05:02 2022 Francois Michaut
** Last update Thu Feb  9 08:55:24 2023 Francois Michaut
**
** IPv4.hpp : Class used to represent and manipulate IPv4 addresses
*/

#pragma once

#include "CppSockets/Address.hpp"

namespace CppSockets {
    class IPv4 : public IAddress {
        public:
            explicit IPv4(std::uint32_t addr);
            explicit IPv4(const char *addr);

            [[nodiscard]]
            std::uint32_t getAddress() const override;

            [[nodiscard]]
            int getFamily() const override;

            [[nodiscard]]
            const std::string &toString() const override;

        private:
            std::uint32_t addr;
            std::string str;
    };
    using EndpointV4 = Endpoint<IPv4>;
}
