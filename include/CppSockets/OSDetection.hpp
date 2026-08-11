/*
** Project LibCppSockets, 2023
**
** Author Francois Michaut
**
** Started on  Tue May  9 23:20:20 2023 Francois Michaut
** Last update Wed Jul  1 14:20:01 2026 Francois Michaut
**
** OSDetection.hpp : OS Detection macros
*/

#pragma once

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__)
  #define OS_WINDOWS 1
#elif defined (__APPLE__)
  #define OS_UNIX 1
  #define OS_APPLE 1
#elif defined(__linux__)
  #define OS_UNIX 1
  #define OS_LINUX 1
#elif defined(__unix__)
  #define OS_UNIX 1
#else
  #error "Unknown OS, please open a issue or pull request to support your OS"
#endif
