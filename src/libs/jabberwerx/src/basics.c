/**
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

#include <event2/event.h>
#ifndef JABBERWERX_NO_BOSH
# include <curl/curl.h>
#endif
#include <ares.h>
#include <jabberwerx/basics.h>
#include <jabberwerx/crypto/tls.h>
#include <jabberwerx/util/log.h>
#include <jwcversion.h>  // generated by build system


static bool _initialized = false;

static const char *_ERR_MSG_TABLE[] = {
    "no error",
    "invalid argument",
    "invalid state",
    "out of memory",
    "buffer overflow",
    "socket connect failure",
    "bad data format",
    "protocol error",
    "timed out",
    "not authorized",
    "not implemented",
    "user-defined error"
};


// PROJECT_VERSION_FULL and PROJECT_VERSION are defined in the generated
// jwcversion.h file
JABBERWERX_API const char* jw_version(bool full)
{
    return (full) ? PROJECT_VERSION_FULL :
                    PROJECT_VERSION;
}

JABBERWERX_API bool jw_global_init(jw_err *err)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    UNUSED_PARAM(err);
    
    if (_initialized)
    {
        jw_log(JW_LOG_DEBUG, "libjabberwerx already initialized");
        return true;
    }

    jw_log(JW_LOG_INFO, "initializing libjabberwerx-%s", PROJECT_VERSION_FULL);

    // use our memory allocators in libevent and curl
    event_set_mem_functions(jw_data_malloc, jw_data_realloc, jw_data_free);
#ifndef JABBERWERX_NO_BOSH
    curl_global_init_mem(CURL_GLOBAL_DEFAULT, jw_data_malloc, jw_data_free,
                         jw_data_realloc, jw_data_strdup, jw_data_calloc);
#endif

    _initialized = true;
    return true;
}

JABBERWERX_API void jw_global_cleanup()
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    if (_initialized)
    {
        jw_log(JW_LOG_INFO,
               "cleaning up libjabberwerx-%s", PROJECT_VERSION_FULL);
    }

#ifndef JABBERWERX_NO_BOSH
    curl_global_cleanup();
#endif
    ares_library_cleanup();
    jw_tls_terminate();

    _initialized = false;
}

JABBERWERX_API const char * jw_err_message(jw_errcode code)
{
    if (JW_ERR_USER < code)
    {
        code = JW_ERR_USER;
    }

    return _ERR_MSG_TABLE[code];
}
