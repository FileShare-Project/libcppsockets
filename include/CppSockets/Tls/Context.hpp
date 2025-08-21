/*
** Project LibCppSockets, 2025
**
** Author Francois Michaut
**
** Started on  Wed Aug 20 14:13:44 2025 Francois Michaut
** Last update Thu Aug 21 14:14:45 2025 Francois Michaut
**
** Context.hpp : Context for TLS sockets
*/

#pragma once

#include "CppSockets/Tls/Utils.hpp"

#include <string_view>

namespace CppSockets {
    class TlsContext {
        public:
            TlsContext();
            TlsContext(SSL_CTX_ptr ptr);
            TlsContext(SSL_CTX *ptr, bool own = true);

            TlsContext(const TlsContext &other) { *this = other; }
            TlsContext(TlsContext &&other) noexcept = default;
            auto operator=(const TlsContext &other) -> TlsContext &;
            auto operator=(TlsContext &&other) noexcept -> TlsContext & = default;

            ~TlsContext();

            void set_min_proto_version(int version);

            void set_verify(int mode, TlsVerifyCallback callback = {});
            void set_verify_depth(int depth);

            void set_certificate(std::string_view cert_path, std::string_view pkey_path);
            [[nodiscard]] auto check_private_key() const -> bool;

            [[nodiscard]] auto get() const -> SSL_CTX * { return m_ptr.get(); }
        private:
            SSL_CTX_ptr m_ptr;
            bool m_own = true;
            TlsVerifyCallback m_verify_callback;

            friend struct TlsContext_Accessor;
    };
}
