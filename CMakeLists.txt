##
## Project CppSockets, 2022
##
## Author Francois Michaut
##
## Started on  Sun Aug 28 19:26:51 2022 Francois Michaut
## Last update Sat Dec  2 10:33:43 2023 Francois Michaut
##
## CMakeLists.txt : CMake to build the CppSockets library
##

cmake_minimum_required (VERSION 3.15)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(BUILD_SHARED_LIBS "Build using shared libraries" ON)

project(LibCppSockets VERSION 0.1.0 LANGUAGES C CXX)
configure_file(include/CppSockets/Version.hpp.in include/CppSockets/Version.hpp)

add_library(cppsockets
  source/Address.cpp
  source/IPv4.cpp
  source/Socket.cpp
  source/TlsSocket.cpp
)
target_include_directories(cppsockets PUBLIC $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include> $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>)
# target_include_directories(cppsockets INTERFACE $<INSTALL_INTERFACE:include>)

find_package(OpenSSL 3.0 COMPONENTS SSL)
target_link_libraries(cppsockets OpenSSL::SSL)

add_custom_target(test
  COMMAND ${CMAKE_COMMAND} --log-level=WARNING
  -B "${CMAKE_CURRENT_BINARY_DIR}/tests"
  -S "${CMAKE_CURRENT_SOURCE_DIR}/tests"
  -G ${CMAKE_GENERATOR}
  COMMAND ${CMAKE_COMMAND} -E cmake_echo_color
  --switch=$(COLOR) --cyan "Building tests..."
  COMMAND ${CMAKE_COMMAND}
  --build "${CMAKE_CURRENT_BINARY_DIR}/tests" -- --quiet
  COMMAND ${CMAKE_MAKE_PROGRAM}
  -C "${CMAKE_CURRENT_BINARY_DIR}/tests" test ARGS=--output-on-failure
  )
