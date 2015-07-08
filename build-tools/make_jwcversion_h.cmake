#
# make_jwcversion_h.cmake
#
# expects definitions set for:
#   top_dir
#   project_name
#
# ensures file jwcversion.h in the current directory is up to date

set ( CMAKE_MODULE_PATH "${top_dir}/build-tools/cmake_modules" )
include ( get_project_version )

file ( WRITE jwcversion.h.in "#define PROJECT_VERSION \"${project_version}\"\n#define PROJECT_VERSION_FULL \"${project_version_full}\"\n" )
execute_process ( COMMAND ${CMAKE_COMMAND} -E copy_if_different jwcversion.h.in jwcversion.h )
