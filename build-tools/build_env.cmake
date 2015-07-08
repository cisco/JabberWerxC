#
# build_env.cmake
#
# expects definitions set for:
#   inc_dirs (list of include dirs, separated with custom separator)
#   lib_dirs (list of lib dirs, separated with custom separator)
#   cmd      (list, including target command and its arguments)
#   list_sep (character sequence used for the list separator)
#   eq_sep   (character sequence used for the '=' separator)
#
# sets LDFLAGS, CPPFLAGS, and (DY)LD_LIBRARY_PATH env vars for a build command

if ( APPLE )
  set ( ldlp DYLD_LIBRARY_PATH )
else ()
  set ( ldlp LD_LIBRARY_PATH )
endif ()

if ( list_sep )
  string ( REPLACE "${list_sep}" ";" inc_dirs "${inc_dirs}" )
  string ( REPLACE "${list_sep}" ";" lib_dirs "${lib_dirs}" )
  string ( REPLACE "${list_sep}" ";" cmd      "${cmd}"      )
endif ()
if ( eq_sep )
  string ( REPLACE "${eq_sep}" "=" cmd "${cmd}" )
endif ()

set ( cppflags "" )
foreach ( dname ${inc_dirs} )
  set ( cppflags "${cppflags}-I${dname} " )
endforeach ()

set ( ldflags "" )
set ( ldlpstr "" )
foreach ( dname ${lib_dirs} )
  set ( ldflags "${ldflags}-L${dname} " )
  set ( ldlpstr "${ldlpstr}${dname}:" )
endforeach ()

set ( ENV{CPPFLAGS} "${cppflags}$ENV{CPPFLAGS}" )
set ( ENV{LDFLAGS}  "${ldflags}$ENV{LDFLAGS}"  )
set ( ENV{${ldlp}}  "${ldlpstr}$ENV{${ldlp}}"  )

string ( REPLACE ";" " " cmd_str "${cmd}" )
#message ( "executing:
#    ${cmd_str}
#  in:
#    $ENV{PWD}
#  with:
#    CPPFLAGS=$ENV{CPPFLAGS}
#    LDFLAGS=$ENV{LDFLAGS}
#    ${ldlp}=$ENV{${ldlp}}"
#)

execute_process ( COMMAND ${cmd} )
