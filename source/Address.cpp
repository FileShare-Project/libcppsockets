/*
** Project CppSocket, 2022
**
** Author Francois Michaut
**
** Started on  Sun Feb 13 22:03:32 2022 Francois Michaut
** Last update Mon Aug 29 20:45:51 2022 Francois Michaut
**
** Address.cpp : Implementation of generic Address classes & functions
*/

#include "CppSockets/Address.hpp"

namespace CppSockets {
    std::string IEndpoint::makeString() const {
        return this->getAddr().toString() + ":" + std::to_string(this->getPort());
    }
}
