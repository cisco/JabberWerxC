/**
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

#ifndef JABBERWERX_TEST_ECHOSRV_H
#define JABBERWERX_TEST_ECHOSRV_H


#include <jabberwerx/util/workq.h>
#include "echosrv_core.h"


#ifdef __cplusplus
extern "C"
{
#endif


typedef struct _jw_test_echosrv *jw_test_echosrv;

#define JW_ECHOSRV_CMD_CLOSE "close"


/**
 * Create and start an echo server bound to the given workq.  Be aware that
 * if the client is running in the same thread as the event loop for the related
 * event_base, then the process can deadlock if so much data is sent in one
 * burst that it fills the socket buffer.  Also, echosrv uses jw_data_malloc and
 * jw_data_free internally, and may be affected if those functions are
 * redefined.  This server can handle only one client per echosrv instance.
 * After the single client disconnects, the echosrv must be destroyed and a new
 * one instantiated before another client can connect.  This function creates
 * an echosrv_core logic module to use internally.  It can be retrieved via the
 * appropriate access function.
 *
 * This function can generate the following errors (set when returning false):
 * \li \c JW_ERR_NO_MEMORY if the internal state could not be allocated
 * \li \c JW_ERR_SOCKET_CONNECT if there was a problem with the listening socket
 *
 * \invariant workq != NULL
 * \invariant echosrv != NULL
 * \param[in] workq The workq that contains the libevent event base to which the
 *                   server events will be bound.
 * \param[out] echosrv The newly created echo server.
 * \param[out] err The error information (provide NULL to ignore)
 * \retval bool true if the echo server was created successfully.
 */
bool _jw_test_echosrv_create(jw_workq   *workq,
                             jw_test_echosrv *echosrv,
                             jw_err          *err);

/**
 * Shutdown and destroy the echo server.
 *
 * \invariant echosrv != NULL
 * \param[in] echosrv The echo server to clean up.
 */
void _jw_test_echosrv_destroy(jw_test_echosrv echosrv);

/**
 * Retrieve the port on 127.0.0.1 on which the server is listening.
 *
 * \invariant echosrv != NULL
 * \param[in] echosrv The echo server.
 * \retval uint16_t The TCP port on which the server socket is listening.
 */
uint16_t _jw_test_echosrv_get_port(jw_test_echosrv echosrv);

/**
 * Retrieve the echosrv_core that this echosrv object uses.
 *
 * \invariant echosrv != NULL
 * \param[in] echosrv The echo server.
 * \retval jw_test_echosrv_core the echosrv_core object
 */
jw_test_echosrv_core _jw_test_echosrv_get_echosrv_core(jw_test_echosrv echosrv);

#ifdef __cplusplus
}
#endif

#endif  /* JABBERWERX_TEST_ECHOSRV_H */
