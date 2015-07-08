#
# simplestream/CMakeLists.txt

set ( srcs
  bind.c
  bind.h
  option_parser.c
  option_parser.h
  sasl_plain.c
  sasl_plain.h
  simplestream.c
  simplestream_defines.h
  simplestream_utils.c
  simplestream_utils.h
)

add_executable ( simplestream ${srcs} )
target_link_libraries ( simplestream LINK_PRIVATE jabberwerx )
