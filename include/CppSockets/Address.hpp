/*
** Project CppSockets, 2022
**
** Author Francois Michaut
**
** Started on  Sun Feb 13 17:09:05 2022 Francois Michaut
** Last update Sat Dec  9 08:52:22 2023 Francois Michaut
**
** Address.hpp : Interface to represent network addresses
*/

#pragma once

#include <cstdint>
#include <string>
#include <type_traits>

// TODO: add parsing functions (eg: from_string()) ?
// TODO: support IPv6 (uint32 for address will not support IPv6)
namespace CppSockets {
    class IAddress {
        public:
            [[nodiscard]] virtual auto getAddress() const -> std::uint32_t = 0;
            [[nodiscard]] virtual auto getFamily() const -> int = 0;
            [[nodiscard]] virtual auto toString() const -> const std::string & = 0;
    };

    class IEndpoint {
        public:
            [[nodiscard]] virtual auto getPort() const -> std::uint16_t = 0;
            [[nodiscard]] virtual auto getAddr() const -> const IAddress & = 0;
            [[nodiscard]] virtual auto toString() const -> const std::string & = 0;

        protected:
            [[nodiscard]] auto makeString() const -> std::string;
    };

    template <class T>
    class Endpoint : public IEndpoint {
        static_assert(std::is_base_of<IAddress, T>::value,
                      "Endpoint address must derive from IAddress"
        );
        public:
            Endpoint(T addr, std::uint16_t port) :
                addr(std::move(addr)), port(port), str(makeString())
            {};
            virtual ~Endpoint() = default;

            [[nodiscard]] auto getPort() const -> std::uint16_t override {
                return port;
            }

            [[nodiscard]] auto getAddr() const -> const T & override {
                return addr;
            }

            [[nodiscard]] auto toString() const -> const std::string & override {
                return str;
            }
        private:
            T addr;
            std::uint16_t port;
            std::string str;
    };
}
