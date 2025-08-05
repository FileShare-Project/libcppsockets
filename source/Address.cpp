/*
** Project CppSocket, 2022
**
** Author Francois Michaut
**
** Started on  Sun Feb 13 22:03:32 2022 Francois Michaut
** Last update Sun Aug  3 21:59:36 2025 Francois Michaut
**
** Address.cpp : Implementation of generic Address classes & functions
*/

#include "CppSockets/Address.hpp"

namespace CppSockets {
    auto IEndpoint::makeString() const -> std::string {
        return this->getAddr().toString() + ":" + std::to_string(this->getPort());
    }
}
