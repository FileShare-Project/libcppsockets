/*
** Project CppSockets, 2022
**
** Author Francois Michaut
**
** Started on  Sun Feb 13 17:09:05 2022 Francois Michaut
** Last update Wed May 27 13:24:39 2026 Francois Michaut
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
            virtual ~IAddress() = default;

            [[nodiscard]] virtual auto get_address() const -> std::uint32_t = 0;
            [[nodiscard]] virtual auto get_family() const -> int = 0;
            [[nodiscard]] virtual auto to_string() const -> const std::string & = 0;
    };

    class IEndpoint {
        public:
            virtual ~IEndpoint() = default;

            [[nodiscard]] virtual auto get_port() const -> std::uint16_t = 0;
            [[nodiscard]] virtual auto get_addr() const -> const IAddress & = 0;
            [[nodiscard]] virtual auto to_string() const -> const std::string & = 0;

        protected:
            [[nodiscard]] auto make_string() const -> std::string;
    };

    template <class T>
    class Endpoint : public IEndpoint {
        // TODO: Replace with new C++ requires
        static_assert(std::is_base_of<IAddress, T>::value,
            "Endpoint address must derive from IAddress"
        );
        public:
            Endpoint(T addr, std::uint16_t port) :
                addr(std::move(addr)), port(port), str(make_string())
            {};
            Endpoint(const Endpoint &other) = default;
            Endpoint(Endpoint &&other) noexcept = default;
            ~Endpoint() override = default;

            auto operator=(const Endpoint &other) -> Endpoint & = default;
            auto operator=(Endpoint &&other) noexcept -> Endpoint & = default;

            [[nodiscard]] auto get_port() const -> std::uint16_t override { return port; }
            [[nodiscard]] auto get_addr() const -> const T & override { return addr; }
            [[nodiscard]] auto to_string() const -> const std::string & override { return str; }
        private:
            T addr;
            std::uint16_t port;
            std::string str;
    };
}
