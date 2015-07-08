#
# CMakeLists.txt

add_custom_target ( examples )

macro ( add_example exname )
  add_subdirectory ( ${exname} )
  add_dependencies ( examples ${exname} )
endmacro()

add_example ( echosrv )
add_example ( simpleclient )
add_example ( simplestream )
