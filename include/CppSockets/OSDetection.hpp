/*
** Project CppSockets, 2023
**
** Author Francois Michaut
**
** Started on  Tue May  9 23:20:20 2023 Francois Michaut
** Last update Sun May 14 14:03:20 2023 Francois Michaut
**
** OSDetection.hpp : OS Detection macros
*/

#pragma once

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__)
  #define OS_WINDOWS
#elif defined (__APPLE__)
  #define OS_UNIX
  #define OS_APPLE
#elif defined(__linux__)
  #define OS_UNIX
  #define OS_LINUX
#elif defined(__unix__)
  #define OS_UNIX
#else
  #error "Unknown compiler, please open a issue or pull request to support your compiler"
#endif
