/*
** Project CppSockets, 2022
**
** Author Francois Michaut
**
** Started on  Sat Jan 15 01:17:42 2022 Francois Michaut
** Last update Wed Aug 20 13:04:47 2025 Francois Michaut
**
** SocketInit.hpp : Socket class automatic initialization and teardown
*/

// Inspired from https://stackoverflow.com/questions/64753466/how-do-i-automatically-implicitly-create-a-instance-of-a-class-at-program-launch/64754436#64754436

namespace CppSockets {
    class SocketInit {
        struct Cleanup {
            ~Cleanup();
        };

        static bool init;
        static Cleanup cleanup;
    };
}
