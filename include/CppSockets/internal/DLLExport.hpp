/*
** Project LibCppSockets, 2026
**
** Author Francois Michaut
**
** Started on  Wed Jul  1 12:30:17 2026 Francois Michaut
** Last update Wed Jul  1 18:54:43 2026 Francois Michaut
**
** DLLExport.hpp : Macros for DLL symbol exporting
*/

#pragma once

#include "CppSockets/OSDetection.hpp"

// TODO: Use theses to export only external symbols and avoid just exporting everything
#if OS_WINDOWS
  #ifdef CPPSOCKETS_DLL_EXPORTS
    // For windows, force the symbol to be exported when building the DLL
    #define CPPSOCKETS_DLL_EXPORT __declspec(dllexport)
  #else
    // For windows, allows client code to know that the symbol must be loaded from the DLL
    #define CPPSOCKETS_DLL_EXPORT __declspec(dllimport)
  #endif
#else
  // For Linux/MacOs force the symbol to be exported
  #define CPPSOCKETS_DLL_EXPORT __attribute__ ((visibility("default")))
#endif
