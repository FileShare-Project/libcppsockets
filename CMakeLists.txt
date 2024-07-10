##
## Project CppSockets, 2022
##
## Author Francois Michaut
##
## Started on  Sun Aug 28 19:26:51 2022 Francois Michaut
## Last update Sat Dec  2 17:45:28 2023 Francois Michaut
##
## CMakeLists.txt : CMake to build the CppSockets library
##

cmake_minimum_required (VERSION 3.15)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(BUILD_SHARED_LIBS "Build using shared libraries" ON)
set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)

project(LibCppSockets VERSION 0.1.0 LANGUAGES C CXX)
configure_file(include/CppSockets/Version.hpp.in include/CppSockets/Version.hpp)

add_library(cppsockets
  source/Address.cpp
  source/IPv4.cpp
  source/Socket.cpp
  source/SocketInit.cpp
  source/TlsSocket.cpp
)
target_include_directories(cppsockets PUBLIC $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include> $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>)

find_package(OpenSSL 3.0 COMPONENTS SSL)
target_link_libraries(cppsockets OpenSSL::SSL)
if(WIN32)
  target_link_libraries(cppsockets wsock32 ws2_32)
endif()

option(CPPSOCKETS_TESTS "TRUE to build the libcppsockets tests" FALSE)
if(CPPSOCKETS_TESTS)
  add_subdirectory(tests)
endif()
