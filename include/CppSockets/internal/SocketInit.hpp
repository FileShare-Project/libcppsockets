/*
** Project LibCppSockets, 2022
**
** Author Francois Michaut
**
** Started on  Sat Jan 15 01:17:42 2022 Francois Michaut
** Last update Wed Jul  1 14:20:05 2026 Francois Michaut
**
** SocketInit.hpp : Socket class automatic initialization and teardown
*/

// Inspired from https://stackoverflow.com/questions/64753466/how-do-i-automatically-implicitly-create-a-instance-of-a-class-at-program-launch/64754436#64754436

#pragma once

namespace CppSockets {
    class SocketInit {
        public:
            SocketInit();

        private:
            struct Cleanup {
                ~Cleanup();
            };

            static const bool init;
            static const Cleanup cleanup;
    };
}
