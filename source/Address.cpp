/*
** Project LibCppSockets, 2022
**
** Author Francois Michaut
**
** Started on  Sun Feb 13 22:03:32 2022 Francois Michaut
** Last update Mon Oct 26 12:40:08 2026 Francois Michaut
**
** Address.cpp : Implementation of generic Address classes & functions
*/

#include "CppSockets/Address.hpp"
#include "CppSockets/IPv4.hpp"

#include <charconv>
#include <stdexcept>

namespace CppSockets {
    auto IEndpoint::make_string() const -> std::string {
        // TODO: For IPv6, the address needs to be surrounded in "[]"
        return this->get_addr().to_string() + ":" + std::to_string(this->get_port());
    }

    auto IEndpoint::from_string(std::string_view endpoint) -> std::shared_ptr<CppSockets::IEndpoint> {
        // TODO: Support IPv6
        std::size_t colon_pos = endpoint.find_last_of(':');

        if (colon_pos == 0 || colon_pos == std::string::npos) {
            throw std::runtime_error("Invalid Endpoint");
        }
        auto port_text = endpoint.substr(colon_pos + 1);

        if (port_text.empty()) {
            throw std::runtime_error("Invalid Endpoint");
        }

        IPv4 ipv4(endpoint.substr(0, colon_pos));

        std::uint16_t port = 0;
        const char *port_start = port_text.data();
        const char *port_end = port_start + port_text.size(); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        const auto [end, ec] = std::from_chars(port_start, port_end, port);

        if (ec != std::errc() || end != port_end) {
            throw std::runtime_error("Invalid port in endpoint");
        }

        return std::make_shared<EndpointV4>(ipv4, port);
    }
}
