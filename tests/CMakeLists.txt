##
## Project CppSockets-Tests, 2022
##
## Author Francois Michaut
##
## Started on  Mon Feb 14 19:35:41 2022 Francois Michaut
## Last update Fri Aug 22 21:12:37 2025 Francois Michaut
##
## CMakeLists.txt : CMake building and running tests for CppSockets
##

include(CTest)

create_test_sourcelist(TestFiles test_driver.cpp
  Tls/TestContext.cpp

  TestSockets.cpp
)

add_executable(unit_tests
  ${TestFiles}
)

target_compile_definitions(unit_tests PRIVATE DEBUG)
target_link_libraries(unit_tests cppsockets)

foreach (test ${TestFiles})
  if (NOT ${test} MATCHES "test_driver.cpp$")
    get_filename_component (DName ${test} DIRECTORY)
    get_filename_component (TName ${test} NAME_WE)
    if (DName STREQUAL "")
      add_test (NAME ${TName} COMMAND unit_tests ${TName})
    else()
      add_test (NAME ${DName}/${TName} COMMAND unit_tests ${DName}/${TName})
    endif()
  endif()
endforeach ()
