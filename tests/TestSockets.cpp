/*
** Project FileShare-Tests, 2022
**
** Author Francois Michaut
**
** Started on  Mon Feb 14 21:17:55 2022 Francois Michaut
** Last update Wed Dec  6 01:34:58 2023 Francois Michaut
**
** TestSockets.cpp : Socket tests
*/

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "CppSockets/Socket.hpp"

#include <iostream>

using namespace CppSockets;

int TestSockets(int, char **)
{
    int child = fork();
    std::string test = "Hello Network !";
    int port = 44444;

    alarm(2);
    if (child != 0) {
        Socket soc(AF_INET, SOCK_STREAM, 0);
        int ret = 0;

        soc.bind("0.0.0.0", port);
        soc.listen(1);
        auto client = soc.accept(nullptr);
        auto buff = client->read();

        if (buff != test) {
            std::cerr << "'" << buff << "' is not equal to expected '" <<
                test << "'" << std::endl;
            return 1;
        }
        waitpid(child, &ret, 0);
        return !(WIFEXITED(ret) && WEXITSTATUS(ret) == 0); // NOLINT(hicpp-signed-bitwise)
    } else {
        Socket soc(AF_INET, SOCK_STREAM, 0);

        while (!soc.connected()) {
            try {
                soc.connect("127.0.0.1", port);
            } catch (std::exception &e) {
                std::cerr << "Got error: " << e.what() << std::endl;
            }
        }
        std::cout << "Connected !" << std::endl;
        soc.write(test);
        return 0;
    }
}
