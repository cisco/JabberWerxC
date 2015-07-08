#
# get_project_version.cmake
#
# expects definitions set for:
#   top_dir
#   project_name
#
# parsers file "version" in ${top_dir} and sets:
#   project_version_major
#   project_version_minor
#   project_version_patch
#   project_version
#   project_version_full

file ( READ "${top_dir}/version" version_str )
string ( REGEX MATCH   "${project_name} ([0-9]+)[.]([0-9]+)[.]([0-9]+)?" version_match "${version_str}" )
set ( project_version_major "${CMAKE_MATCH_1}" )
set ( project_version_minor "${CMAKE_MATCH_2}" )
set ( project_version_patch "${CMAKE_MATCH_3}" )

set ( project_version ${project_version_major}.${project_version_minor} )
set ( project_version_full ${project_version}.${project_version_patch} )
