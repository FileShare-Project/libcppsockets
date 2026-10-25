/*
** Project LibCppSockets, 2022
**
** Author Francois Michaut
**
** Started on  Mon Oct 26 09:37:12 2026 Francois Michaut
** Last update Mon Oct 26 09:48:55 2026 Francois Michaut
**
** PollEvent.hpp : Helper enum for Socket::poll()
*/

#pragma once

#include <cstdint>

namespace CppSockets {
    class PollEvent {
        public:
            enum Value : std::uint8_t {
                NONE = 0,
                READ = 1,
                WRITE = 2,
            };

            constexpr PollEvent() : m_value(Value::NONE) {}
            constexpr PollEvent(Value value) : m_value(value) {}

            constexpr auto operator|=(PollEvent other) -> PollEvent & {
                m_value = static_cast<Value>(to_uint(m_value) | to_uint(other.m_value));
                return *this;
            }
            constexpr auto operator&=(PollEvent other) -> PollEvent & {
                m_value = static_cast<Value>(to_uint(m_value) & to_uint(other.m_value));
                return *this;
            }
            [[nodiscard]] constexpr auto operator|(PollEvent other) const -> PollEvent {
                other |= *this;
                return other;
            }
            [[nodiscard]] constexpr auto operator&(PollEvent other) const -> PollEvent {
                other &= *this;
                return other;
            }
            [[nodiscard]] constexpr auto operator==(PollEvent other) const -> bool { return m_value == other.m_value; }
            [[nodiscard]] constexpr auto operator!=(PollEvent other) const -> bool { return m_value != other.m_value; }

            explicit constexpr operator bool() const { return m_value != Value::NONE; }

            [[nodiscard]] constexpr auto has(PollEvent event) const -> bool {
                return (to_uint(m_value) & to_uint(event.m_value)) != 0;
            }
            [[nodiscard]] constexpr auto value() const -> Value { return m_value; }

        private:
            static constexpr auto to_uint(Value value) -> std::uint8_t {
                return static_cast<std::uint8_t>(value);
            }

            Value m_value;
    };
}
