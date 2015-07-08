#
# doc/CMakeLists.txt

set ( src_docs
  api-design.rst
  developerGuide.html
  events.rst
  gettingStartedGuide.html
  index.html
  jabberwerx.css
  third_party.rst
)

include ( FindDoxygen )

add_custom_target ( doc
  COMMAND ${CMAKE_COMMAND} -E make_directory ${dist_dir}/doc
)

foreach ( src ${src_docs} )
  add_custom_command ( TARGET doc POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/${src} ${dist_dir}/doc/
  )
endforeach ()

if ( NOT DOXYGEN_EXECUTABLE )
  message ( "doxygen not found; disabling API documentation generation" )
else ()
  set ( top_dir ${CMAKE_SOURCE_DIR} )
  include ( get_project_version )
  set ( api_doc_out_dir "${dist_dir}/doc/api" )
  configure_file (
    "${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile.in"
    "${CMAKE_CURRENT_BINARY_DIR}/Doxyfile" )

  add_custom_target ( doxygen
    COMMAND ${CMAKE_COMMAND} -E make_directory ${api_doc_out_dir}
    COMMAND ${DOXYGEN_EXECUTABLE} "${CMAKE_CURRENT_BINARY_DIR}/Doxyfile"
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}/src/libs/jabberwerx"
  )

  add_dependencies ( doc doxygen )
endif ()
