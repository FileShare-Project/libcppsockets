/*
** Project LibCppSockets, 2022
**
** Author Francois Michaut
**
** Started on  Sun Feb 13 22:03:32 2022 Francois Michaut
** Last update Wed Jul  1 14:19:53 2026 Francois Michaut
**
** Address.cpp : Implementation of generic Address classes & functions
*/

#include "CppSockets/Address.hpp"
#include "CppSockets/IPv4.hpp"

#include <sstream>

namespace CppSockets {
    auto IEndpoint::make_string() const -> std::string {
        // TODO: For IPv6, the address needs to be surrounded in "[]"
        return this->get_addr().to_string() + ":" + std::to_string(this->get_port());
    }

    // TODO: Find a better way to use string_view
    auto IEndpoint::from_string(std::string_view endpoint) -> std::shared_ptr<CppSockets::IEndpoint> {
        return from_string(std::string(endpoint));
    }

    auto IEndpoint::from_string(std::string endpoint) -> std::shared_ptr<CppSockets::IEndpoint> {
        // TODO: Support IPv6
        std::size_t colon_pos = endpoint.find_last_of(':');
        std::stringstream ss{std::move(endpoint)};
        std::string ip_part(colon_pos, '\0'); // 0-init str with enough size
        std::uint16_t port = 0;

        ss.read(ip_part.data(), colon_pos);

        IPv4 ipv4(ip_part.c_str());

        ss.ignore(1, ':');
        if (ss) {
            ss >> port;
        }

        return std::make_shared<EndpointV4>(ipv4, port);
    }
}
