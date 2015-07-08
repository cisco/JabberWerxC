#
# CMakeLists.txt
#
# top level build file for the JabberWerxC project

cmake_minimum_required ( VERSION 2.8.11 )
project ( "JabberWerxC" )

# set a default/check the build type if we are not generating a
# multi-configuration build system
if ( NOT CMAKE_CONFIGURATION_TYPES )
  set ( build_type_help
    "Options are: None(CMAKE_C_FLAGS used from environment) Debug Release RelWithDebInfo MinSizeRel" )
  set ( build_type_regex "None|Debug|Release|RelWithDebInfo|MinSizeRel" )
  if ( CMAKE_BUILD_TYPE )
    set ( CMAKE_BUILD_TYPE ${CMAKE_BUILD_TYPE} CACHE STRING ${build_type_help} FORCE )
    if ( NOT CMAKE_BUILD_TYPE MATCHES "^(${build_type_regex})$" )
      message ( FATAL_ERROR "unknown build type: '${CMAKE_BUILD_TYPE}'; ${build_type_help}" )
    endif ()
  else ()
    message ( STATUS "-DCMAKE_BUILD_TYPE=${build_type_regex} not specified; defaulting to 'Debug'" )
    set ( CMAKE_BUILD_TYPE Debug CACHE STRING ${build_type_help} FORCE )
  endif ()
  set_property ( CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "None" "Debug" "Release" "MinSizeRel" "RelWithDebInfo" )
endif ()

# descriptions here must be short to fit in the ccmake ui.  see the README
# file for more complete info.
option ( build_examples    "Build example applications"                    ON  )
option ( build_jwcunicode  "Build jwcunicode, has extra prerequisites"     OFF )
option ( build_tests       "Build unit tests; run via the 'test' target"   ON  )
option ( do_coverage       "Create coverage report after unit test run"    OFF )
option ( enable_bosh       "Enable the bosh module via the curl library"   ON  )
option ( enable_stringprep "Enable character set normalization via libidn" ON  )
option ( enable_tls        "Enable crypto for socket streams via openssl"  ON  )
option ( fatal_warnings    "Treat build warnings as errors"                OFF )

set ( scripts_dir  ${CMAKE_SOURCE_DIR}/build-tools )
set ( dist_dir     ${CMAKE_BINARY_DIR}/dist        )
set ( download_dir ${CMAKE_BINARY_DIR}/downloads   )

set ( CMAKE_MODULE_PATH ${scripts_dir}/cmake_modules )
set ( CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${dist_dir}/lib )
set ( CMAKE_LIBRARY_OUTPUT_DIRECTORY ${dist_dir}/lib )
set ( CMAKE_RUNTIME_OUTPUT_DIRECTORY ${dist_dir}/bin )

if (NOT DEFINED CMAKE_MACOSX_RPATH)
  set(CMAKE_MACOSX_RPATH 0)
endif()

add_subdirectory ( doc )
add_subdirectory ( src )

set ( package_prefix ${CMAKE_PROJECT_NAME}-${CMAKE_SYSTEM_NAME}-${CMAKE_BUILD_TYPE} )
add_custom_target ( package DEPENDS examples test doc
  COMMAND ${CMAKE_COMMAND} -Dtop_dir=${CMAKE_SOURCE_DIR}
      -Dproject_name=${CMAKE_PROJECT_NAME} -Ddist_dir=${dist_dir}
      -Dpackage_prefix=${package_prefix} -P ${scripts_dir}/make_package.cmake
)
