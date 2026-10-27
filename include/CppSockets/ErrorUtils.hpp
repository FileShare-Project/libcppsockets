/*
** Project LibCppSockets, 2026
**
** Author Francois Michaut
**
** Started on  Mon Oct 26 22:24:25 2026 Francois Michaut
** Last update Mon Oct 26 22:44:34 2026 Francois Michaut
**
** ErrorUtils.hpp : Portable system error utilities
*/

#pragma once

#include <string>

namespace CppSockets {
    auto get_errno() -> int;
    auto strerror(int err) -> std::string;
    auto strerror() -> std::string;
}
