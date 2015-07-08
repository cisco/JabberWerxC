#
# echosrv/CMakeLists.txt

set ( srcs
  echosrv.c
)

add_executable ( echosrv ${srcs} )
target_link_libraries ( echosrv LINK_PRIVATE jabberwerx )
