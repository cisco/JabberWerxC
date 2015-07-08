#
# make_package.cmake
#
# expects definitions set for:
#   top_dir
#   project_name
#   dist_dir
#   package_prefix
#
# ensures file jwcversion.h in the current directory is up to date

set ( CMAKE_MODULE_PATH "${top_dir}/build-tools/cmake_modules" )
include ( get_project_version )

set ( package_fname "${package_prefix}-${project_version_full}.tgz" )
string ( TOLOWER ${package_fname} package_fname )
message ( STATUS "packaging ${package_fname}" )
execute_process ( 
  COMMAND ${CMAKE_COMMAND} -E tar czf ${package_fname} bin doc include lib
  WORKING_DIRECTORY ${dist_dir}
)
execute_process ( 
  COMMAND sha1sum ${package_fname}
  OUTPUT_FILE ${package_fname}.sha
  WORKING_DIRECTORY ${dist_dir}
)
