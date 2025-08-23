/*
** Project FileShare-Tests, 2025
**
** Author Francois Michaut
**
** Started on  Fri Aug 22 21:09:12 2025 Francois Michaut
** Last update Fri Aug 22 21:36:06 2025 Francois Michaut
**
** TestContext.cpp : TlsContext tests
*/

#include "CppSockets/Tls/Context.hpp"
#include "CppSockets/Tls/Socket.hpp"

void TestConfigCopyCtor() {
    CppSockets::TlsContext ctx;
    CppSockets::TlsSocket soc;

    soc = CppSockets::TlsSocket(AF_INET, SOCK_STREAM, 0, ctx);
    soc = CppSockets::TlsSocket(AF_INET, SOCK_STREAM, 0, ctx);
    soc = CppSockets::TlsSocket(AF_INET, SOCK_STREAM, 0, ctx);
    soc = CppSockets::TlsSocket(AF_INET, SOCK_STREAM, 0, ctx);
    soc = CppSockets::TlsSocket(AF_INET, SOCK_STREAM, 0, ctx);

    soc = CppSockets::TlsSocket(AF_INET, SOCK_STREAM, 0, ctx);
    soc = CppSockets::TlsSocket(AF_INET, SOCK_STREAM, 0, ctx);
    soc = CppSockets::TlsSocket(AF_INET, SOCK_STREAM, 0, ctx);
    soc = CppSockets::TlsSocket(AF_INET, SOCK_STREAM, 0, ctx);
    soc = CppSockets::TlsSocket(AF_INET, SOCK_STREAM, 0, ctx);
}

auto Tls_TestContext(int /* ac */, char ** const /* av */) -> int
{
    TestConfigCopyCtor();
    return 0;
}
