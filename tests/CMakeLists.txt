##
## Project CppSockets-Tests, 2022
##
## Author Francois Michaut
##
## Started on  Mon Feb 14 19:35:41 2022 Francois Michaut
## Last update Sun Aug 28 19:55:12 2022 Francois Michaut
##
## CMakeLists.txt : CMake building and running tests for CppSockets
##

cmake_minimum_required (VERSION 3.15)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

project(CppSockets-Tests VERSION 0.1.0 LANGUAGES C CXX)

include(CTest)

create_test_sourcelist(TestFiles test_driver.cpp
  TestSockets.cpp
  )

add_executable(unit_tests
  ../source/Address.cpp
  ../source/Socket.cpp
  ../source/IPv4.cpp
  ${TestFiles}
  )

foreach (test ${TestFiles})
  if (NOT ${test} STREQUAL test_driver.cpp)
    get_filename_component (DName ${test} DIRECTORY)
    get_filename_component (TName ${test} NAME_WE)
    if (DName STREQUAL "")
      add_test (NAME ${TName} COMMAND unit_tests ${TName})
    else()
      add_test (NAME ${DName}/${TName} COMMAND unit_tests ${DName}/${TName})
    endif()
  endif()
endforeach ()

include_directories(
  "${CMAKE_CURRENT_BINARY_DIR}"
  "${CMAKE_CURRENT_SOURCE_DIR}"
  "${CMAKE_CURRENT_SOURCE_DIR}/../include"
)
