/**
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

#ifndef JABBERWERX_TEST_HTTPSRV_H
#define JABBERWERX_TEST_HTTPSRV_H

#include <event2/event.h>
#include <jabberwerx/basics.h>


#ifdef __cplusplus
extern "C"
{
#endif


typedef struct _jw_httpsrv *jw_httpsrv;

/**
 * Create and start a http server bound to the given event_base.  Be aware that
 * if the client is running in the same thread as the event loop for this
 * event_base, then the process can deadlock if so much data is sent in one
 * burst that it fills the socket buffers.  Also, httpsrv uses jw_data_malloc
 * and jw_data_free internally, and may be affected if clients redefine
 * implementations of those functions.  This server can handle any number of
 * requests before it is destroyed, but all requests must be complete before
 * destroy is called.
 */
bool jw_httpsrv_create(struct event_base *evbase,
                       jw_httpsrv        *httpsrv,
                       jw_err            *err);

/**
 * Shutdown and destroy the http server.
 */
void jw_httpsrv_destroy(jw_httpsrv httpsrv);

/**
 * Retrieve the port on 127.0.0.1 on which the server is listening.
 */
uint16_t jw_httpsrv_get_port(jw_httpsrv httpsrv);

/**
 * Set the next response code and body.  The body can be NULL.  If this function
 * is not called again before the following response, that response will default
 * back to an empty 200 reply.
 */
bool jw_httpsrv_set_next_response(
        jw_httpsrv httpsrv, int status_code, const char *body);

#ifdef __cplusplus
}
#endif

#endif  // JABBERWERX_TEST_HTTPSRV_H
