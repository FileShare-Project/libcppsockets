/*
** Project CppSockets, 2022
**
** Author Francois Michaut
**
** Started on  Sun Feb 13 17:09:05 2022 Francois Michaut
** Last update Mon Aug 29 20:46:03 2022 Francois Michaut
**
** Address.hpp : Interface to represent network addresses
*/

#pragma once

#include <string>
#include <type_traits>

namespace CppSockets {
    class IAddress {
        public:
            [[nodiscard]]
            virtual std::uint32_t getAddress() const = 0;
            [[nodiscard]]
            virtual int getFamily() const = 0;
            [[nodiscard]]
            virtual const std::string &toString() const = 0;
    };

    class IEndpoint {
        public:
            [[nodiscard]]
            virtual int getPort() const = 0;
            [[nodiscard]]
            virtual const IAddress &getAddr() const = 0;
            [[nodiscard]]
            virtual const std::string &toString() const = 0;

        protected:
            [[nodiscard]]
            std::string makeString() const;
    };

    template <class T>
    class Endpoint : public IEndpoint {
        static_assert(std::is_base_of<IAddress, T>::value,
                      "Endpoint address must derive from IAddress"
        );
        public:
            Endpoint(T addr, int port) :
                addr(std::move(addr)), port(port), str(makeString())
            {};

            [[nodiscard]]
            int getPort() const override {
                return port;
            }

            [[nodiscard]]
            const T &getAddr() const override {
                return addr;
            }

            [[nodiscard]]
            const std::string &toString() const override {
                return str;
            }
        private:
            int port;
            T addr;
            std::string str;
    };
}
