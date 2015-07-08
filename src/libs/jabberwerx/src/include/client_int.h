/**
 * \file
 * \brief
 * Client typedefs.  Private, not for use outside library and unit tests.
 *
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

#ifndef JABBERWERX_CLIENT_INT_H
#define JABBERWERX_CLIENT_INT_H

#include "timer.h"
#include <jabberwerx/basics.h>
#include <jabberwerx/client.h>
#include <jabberwerx/util/htable.h>

#ifdef __cplusplus
extern "C"
{
#endif

typedef enum
{
    SM_SUPPORTED      = 0x1, // server supports stream management
    SM_REQUIRED       = 0x2, // server requires stream management
    SM_ENABLED        = 0x4, // server responded with enabled elem
    SM_RESUME_ENABLED = 0x8  // resuming enabled for this stream
} _stream_mgmt_flags;

typedef struct _stanza_queue_int
{
    jw_dom_node         *stanza;
    struct _stanza_queue_int *next;
} *_stanza_queue;

typedef struct _stream_mgmt_state_int
{
    _stream_mgmt_flags flags;

    char *resume_id;       // the opaque server-generated id to use for resuming
    char *resume_location; // the host:port string to reconnect to for resuming

    uint32_t num_received_stanzas;     // client "h"
    uint32_t num_server_acked_stanzas; // last known server "h"

    // when the num_unacked_stanzas counter crosses ack_request_threshold, an
    // ack request is sent to the server.  When the server responds with an ack,
    // we decrement the counter by (acknum - num_server_acked_stanzas), remove
    // the appropriate number of stanzas from unacked_stanzas, and update
    // num_server_acked_stanzas.  If num_unacked_stanzas is still greater than
    // ack_request_threshold at that point, we send another ack request.
    uint32_t ack_request_threshold;
    uint32_t num_unacked_stanzas;
    _stanza_queue unacked_stanzas;
    _stanza_queue unacked_stanzas_tail;

    jw_timer *ack_request_timer;
} *_stream_mgmt_state;

_stream_mgmt_state _jw_client_get_stream_mgmt_state(jw_client *client);

//some protected reconnect functions exposed for unit tests
/**
 * Get the given client's reconnect state structure
 */
jw_client_reconnect_status *_jw_client_reconnect_state(jw_client *client);

/**
 * compute the next countdown from the base and # of attempts
 */
uint32_t _jw_client_reconn_next_countdown(uint32_t base, uint32_t attempt);

/**
 * return true if the given error is a disconnect error that should start a
 * reconnect. error is an error recieved after the client has been fully
 * connected and authenticated.
 */
bool _jw_client_reconn_is_disconnect_error(jw_dom_node *error);


#ifdef __cplusplus
}
#endif

#endif // JABBERWERX_CLIENT_INT_H
