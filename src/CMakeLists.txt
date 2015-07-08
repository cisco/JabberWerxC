#
# src/CMakeLists.txt

# set general compilation flags
if ( CMAKE_C_COMPILER_ID STREQUAL "GNU" OR CMAKE_C_COMPILER_ID STREQUAL "Clang" )
  add_definitions ( -std=gnu99 -Wall -Wextra -pedantic )
  if ( fatal_warnings )
    add_definitions ( -Werror )
  endif ()
elseif ( MSVC )
  add_definitions ( /W3 )
  if ( fatal_warnings )
    add_definitions ( /WX )
  endif ()
else ()
  message ( FATAL_ERROR "unhandled compiler id: ${CMAKE_C_COMPILER_ID}" )
endif ()

add_subdirectory ( libs )

if ( build_examples )
  # looser standards for examples
  remove_definitions ( -pedantic )
  add_subdirectory ( examples )
endif ()
