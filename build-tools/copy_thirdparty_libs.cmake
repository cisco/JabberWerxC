#
# copy_thirdparty_libs.cmake
#
# expects definitions set for:
#   src_dir
#   dest_dir
#   glob_str
#
# copies built shared objects from src_dir to dest_dir

file ( GLOB files RELATIVE ${src_dir} ${src_dir}/${glob_str} )

execute_process (
  COMMAND ${CMAKE_COMMAND} -E tar cf ${CMAKE_CURRENT_BINARY_DIR}/libs.tar ${files}
  WORKING_DIRECTORY ${src_dir}
)
execute_process (
  COMMAND ${CMAKE_COMMAND} -E tar xf ${CMAKE_CURRENT_BINARY_DIR}/libs.tar
  WORKING_DIRECTORY ${dest_dir}
)
