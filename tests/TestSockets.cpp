/*
** Project FileShare-Tests, 2022
**
** Author Francois Michaut
**
** Started on  Mon Feb 14 21:17:55 2022 Francois Michaut
** Last update Mon Aug 29 20:46:38 2022 Francois Michaut
**
** TestSockets.cpp : Socket tests
*/

#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "CppSockets/Socket.hpp"

#include <iostream>

using namespace CppSockets;

int TestSockets(int, char **)
{
    int child = fork();
    std::string test = "Hello Network !";
    int port = 44444;

    alarm(10);
    if (child == 0) {
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
        return !(WIFEXITED(ret) && WEXITSTATUS(ret) == 0); // NOLINT
    } else {
        Socket soc(AF_INET, SOCK_STREAM, 0);

        while (!soc.isConnected()) {
            try {
                soc.connect("127.0.0.1", port);
            } catch (std::exception &e) {
                std::cerr << e.what() << std::endl;
            }
        }
        std::cout << "Connected !" << std::endl;
        soc.write(test);
        return 0;
    }
}
