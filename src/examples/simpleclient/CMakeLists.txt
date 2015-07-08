#
# simpleclient/CMakeLists.txt

set ( srcs
  option_parser.c
  option_parser.h
  simpleclient.c
  simpleclient_utils.c
  simpleclient_utils.h
)

add_executable ( simpleclient ${srcs} )
target_link_libraries ( simpleclient LINK_PRIVATE jabberwerx )
