#
# jabberwerx/CMakeLists.txt

# when you add a file to the project, please also add it to the corresponding
# list below.  keep the list alphabetized for easy searching.

set ( include_public
  include/jabberwerx/basics.h
  include/jabberwerx/client.h
  include/jabberwerx/crypto/sha1.h
  include/jabberwerx/crypto/tls.h
  include/jabberwerx/dom.h
  include/jabberwerx/eventing.h
  include/jabberwerx/jabberwerx.h
  include/jabberwerx/jid.h
  include/jabberwerx/sasl_factory.h
  include/jabberwerx/sasl_mech.h
  include/jabberwerx/stream.h
  include/jabberwerx/tracker.h
  include/jabberwerx/types-compat.h
  include/jabberwerx/util/base64.h
  include/jabberwerx/util/hex.h
  include/jabberwerx/util/htable.h
  include/jabberwerx/util/log.h
  include/jabberwerx/util/mem.h
  include/jabberwerx/util/parser.h
  include/jabberwerx/util/serializer.h
  include/jabberwerx/util/states.h
  include/jabberwerx/util/str.h
  include/jabberwerx/util/workq.h
)

set ( include_private
  src/include/bosh_conn_int.h
  src/include/client_int.h
  src/include/dom_int.h
  src/include/eventing_int.h
  src/include/log_int.h
  src/include/pool_types.h
  src/include/sasl_int.h
  src/include/stream_int.h
  src/include/timer.h
  src/include/tls_int.h
  src/include/unicode_int.h
  src/include/utils.h
)

set ( src_main
  src/basics.c
  src/client.c
  src/dom.c
  src/eventing.c
  src/jid.c
  src/stream.c
  src/tracker.c
)

set ( src_crypto
  src/crypto/sha1.c
  src/crypto/sha1_openssl.c
  src/crypto/tls.c
  src/crypto/tls_openssl.c
)

set ( src_sasl
  src/sasl/sasl_mech_external.c
  src/sasl/sasl_mech_plain.c
  src/sasl_factory.c
  src/sasl_mech.c
)

set ( src_stream
  src/stream/bosh.c
  src/stream/bosh_conn.c
  src/stream/socket.c
)

set ( src_util
  src/util/base64.c
  src/util/hex.c
  src/util/htable.c
  src/util/log.c
  src/util/mem.c
  src/util/parser.c
  src/util/serializer.c
  src/util/states.c
  src/util/str.c
  src/util/timer.c
  src/util/unicode.c
  src/util/utils.c
  src/util/workq.c
)

set ( jabberwerx_srcs
  ${include_public} ${include_private}
  ${src_main} ${src_crypto} ${src_sasl} ${src_stream} ${src_util}
)

set ( src_tests
  test/base64_test.c
  test/basics_test.c
  test/bosh_conn_test.c
  test/bosh_test.c
  test/client_test.c
  test/dom_test.c
  test/echosrv.c
  test/echosrv.h
  test/echosrv_core.c
  test/echosrv_core.h
  test/error_test.c
  test/eventing_test.c
  test/hex_test.c
  test/htable_test.c
  test/httpsrv.c
  test/httpsrv.h
  test/jid_test.c
  test/log_test.c
  test/mem_test.c
  test/mock_stream.c
  test/mock_stream.h
  test/parser_test.c
  test/sasl_test.c
  test/serializer_test.c
  test/sha1_test.c
  test/socket_test.c
  test/stanza_defines.h
  test/states_test.c
  test/str_test.c
  test/stream_test.c
  test/stream_test.h
  test/test-jabberwerx.c
  test/test_utils.c
  test/test_utils.h
  test/tls_test.c
  test/tracker_test.c
  test/workq_test.c
)

set ( jabberwerx_test_srcs ${src_tests} )

find_package( PkgConfig REQUIRED )

add_library ( jabberwerx SHARED ${jabberwerx_srcs} jwcversion.h )
target_include_directories ( jabberwerx PUBLIC include )
target_include_directories ( jabberwerx PRIVATE ${CMAKE_CURRENT_BINARY_DIR} )

pkg_check_modules ( EXPAT REQUIRED expat=2.1.0 )
target_include_directories ( jabberwerx PRIVATE ${EXPAT_INCLUDE_DIRS} )
target_link_libraries ( jabberwerx PRIVATE ${EXPAT_LDFLAGS} )

pkg_check_modules ( CARES REQUIRED libcares )
target_include_directories ( jabberwerx PRIVATE ${CARES_INCLUDE_DIRS} )
target_link_libraries ( jabberwerx PRIVATE ${CARES_LDFLAGS} )

pkg_check_modules ( LIBEVENT REQUIRED libevent )
target_include_directories ( jabberwerx PRIVATE ${LIBEVENT_INCLUDE_DIRS} )
target_link_libraries ( jabberwerx PUBLIC ${LIBEVENT_LDFLAGS} )
target_link_libraries ( jabberwerx PRIVATE event_extra )

if ( enable_bosh )
  find_package ( CURL REQUIRED )
  target_include_directories ( jabberwerx PRIVATE ${CURL_INCLUDE_DIRS} )
  target_link_libraries ( jabberwerx PRIVATE ${CURL_LIBRARIES} )
else ()
  target_compile_definitions ( jabberwerx PRIVATE JABBERWERX_NO_BOSH )
endif ()

if ( enable_stringprep )
  pkg_check_modules ( LIBIDN REQUIRED libidn )
  target_compile_definitions ( jabberwerx PRIVATE JABBERWERX_STRINGPREP_IDN )
  target_include_directories ( jabberwerx PRIVATE ${LIBIDN_INCLUDE_DIRS} )
  target_link_libraries ( jabberwerx PRIVATE idn )
else ()
  target_compile_definitions ( jabberwerx PRIVATE JABBERWERX_STRINGPREP_ASCII )
endif ()

if ( enable_tls )
  find_package ( OpenSSL 1.0 REQUIRED )
  target_include_directories ( jabberwerx PRIVATE ${OPENSSL_INCLUDE_DIR} )
  target_link_libraries ( jabberwerx PRIVATE event_openssl )
  target_link_libraries ( jabberwerx PRIVATE  ${OPENSSL_LIBRARIES} )
else ()
  target_compile_definitions ( jabberwerx PRIVATE JABBERWERX_TLS_NONE )
endif ()

if ( APPLE )
  target_compile_definitions ( jabberwerx PRIVATE MAC_OS_X_VERSION_MIN_REQUIRED=MAC_OS_X_VERSION_10_6 )
endif ()

set(CMAKE_COMPILER_IS_CLANGXX 0)
if ()
  set(CMAKE_COMPILER_IS_CLANGXX 1)
endif ()

if ( do_coverage )
  if ( CMAKE_COMPILER_IS_GNUCXX)
    set_property ( TARGET jabberwerx APPEND_STRING PROPERTY COMPILE_FLAGS "-fprofile-arcs -ftest-coverage" )
    target_link_libraries ( jabberwerx LINK_PRIVATE gcov )
  elseif ( "${CMAKE_CXX_COMPILER_ID}" MATCHES "Clang")
    set_property ( TARGET jabberwerx APPEND_STRING PROPERTY COMPILE_FLAGS "--coverage" )
    set_property ( TARGET jabberwerx APPEND_STRING PROPERTY LINK_FLAGS "--coverage" )
    #target_link_libraries ( jabberwerx LINK_PRIVATE profile_rt )
  elseif ( MSVC )
    message ( FATAL_ERROR "not yet implemented" )
  else ()
    message ( FATAL_ERROR "unhandled build environment" )
  endif ()
endif ()

add_custom_command ( OUTPUT jwcversion.h
  DEPENDS ${CMAKE_SOURCE_DIR}/version
  COMMAND ${CMAKE_COMMAND} -Dtop_dir=${CMAKE_SOURCE_DIR} -Dproject_name=${CMAKE_PROJECT_NAME} -P ${scripts_dir}/make_jwcversion_h.cmake
)

add_custom_command ( TARGET jabberwerx POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy_directory ${CMAKE_CURRENT_SOURCE_DIR}/include ${dist_dir}/include
)

if ( NOT build_tests )
  add_custom_target ( test
    COMMENT "unit tests are disabled; run 'ccmake ..' to modify the configuration" )
else ()
  add_executable ( jabberwerx-test ${jabberwerx_test_srcs} )
  target_link_libraries ( jabberwerx-test LINK_PRIVATE jabberwerx expat )
  if ( enable_bosh )
    target_link_libraries ( jabberwerx-test LINK_PRIVATE curl )
  endif ()
  target_include_directories ( jabberwerx-test PRIVATE ${CMAKE_SOURCE_DIR}/src/third_party/fctx )
  add_custom_target ( test
    ${CMAKE_COMMAND} -Dlib_dirs=${dist_dir}/lib -Dcmd=./jabberwerx-test -P ${scripts_dir}/build_env.cmake
    DEPENDS jabberwerx-test
    WORKING_DIRECTORY ${dist_dir}/bin
  )

  # coverage report
  if ( do_coverage )
    if ( CMAKE_COMPILER_IS_GNUCXX OR ("${CMAKE_CXX_COMPILER_ID}" MATCHES "Clang"))
      add_custom_command ( TARGET test POST_BUILD
        COMMAND geninfo --base-directory=${CMAKE_CURRENT_SOURCE_DIR}
            --output-file=jabberwerx.lcov.full ${CMAKE_CURRENT_BINARY_DIR}
        COMMAND lcov --remove jabberwerx.lcov.full /usr/include/*
            /usr/include/*/* /usr/include/*/*/*
            ${CMAKE_BINARY_DIR}/src/third_party/*/*/*/*/*
            --output-file=jabberwerx.lcov
        COMMAND genhtml --output-directory=${CMAKE_BINARY_DIR}/coverage
            jabberwerx.lcov
      )
    elseif ( MSVC )
      message ( FATAL_ERROR "not yet implemented" )
    else ()
      message ( FATAL_ERROR "unhandled build environment" )
    endif ()
  endif ()

  # valgrind
  if ( NOT WIN32 )
    get_target_property ( test_out_dir jabberwerx-test RUNTIME_OUTPUT_DIRECTORY )
    add_custom_target ( valgrind
      valgrind --tool=memcheck --leak-check=full --show-reachable=yes
          --dsymutil=yes --track-origins=yes --num-callers=50
          --error-exitcode=1 --suppressions=${scripts_dir}/vg-suppressed.supp
          ./jabberwerx-test
      DEPENDS jabberwerx-test
      WORKING_DIRECTORY ${test_out_dir} )
  endif ()
endif ()

# create source groups for visual studio
if ( MSVC )
  source_group ( "Include"          FILES ${include_public}  )
  source_group ( "Internal Include" FILES ${include_private} jwcversion.h )
  source_group ( "Main"             FILES ${src_main}        )
  source_group ( "Crypto"           FILES ${src_crypto}      )
  source_group ( "Sasl"             FILES ${src_sasl}        )
  source_group ( "Stream"           FILES ${src_stream}      )
  source_group ( "Util"             FILES ${src_util}        )
  source_group ( "Tests"            FILES ${src_tests}       )
endif ()
