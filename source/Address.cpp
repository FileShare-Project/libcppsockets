/*
** Project CppSocket, 2022
**
** Author Francois Michaut
**
** Started on  Sun Feb 13 22:03:32 2022 Francois Michaut
** Last update Wed Aug 20 12:58:08 2025 Francois Michaut
**
** Address.cpp : Implementation of generic Address classes & functions
*/

#include "CppSockets/Address.hpp"

namespace CppSockets {
    auto IEndpoint::make_string() const -> std::string {
        return this->get_addr().to_string() + ":" + std::to_string(this->get_port());
    }
}
