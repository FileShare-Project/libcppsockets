##
## Project CppSockets-Tests, 2022
##
## Author Francois Michaut
##
## Started on  Mon Feb 14 19:35:41 2022 Francois Michaut
## Last update Sat Dec  2 17:46:03 2023 Francois Michaut
##
## CMakeLists.txt : CMake building and running tests for CppSockets
##

include(CTest)

create_test_sourcelist(TestFiles test_driver.cpp
  TestSockets.cpp
)

add_executable(unit_tests
  ${TestFiles}
)

target_compile_definitions(unit_tests PRIVATE DEBUG)
target_link_libraries(unit_tests cppsockets)

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
