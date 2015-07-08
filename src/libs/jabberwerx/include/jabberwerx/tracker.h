/**
 * \file
 * \brief
 * Functions and data structures for tracking IQs and XDBs.
 *
 *
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

#ifndef JABBERWERX_TRACKER_H
#define JABBERWERX_TRACKER_H

#include <event2/event.h>
#include "eventing.h"
#include "dom.h"


/** A tracker for outstanding IQ and XDB requests. */
typedef struct _jw_tracker_t jw_tracker;


/**
 * Called when the result comes back or when a timeout occurs.  On
 * timeout, the result will be NULL. If a timeout occurs the callback
 * will NOT be fired for the result when it finally does arrive.
 *
 * NOTE: If the underlying jw_stream is closed before a result has
 *       returned a timeout condition is assumed.
 *
 * \param[in] result The result of the given request, matched by ID,
 *     stanza type, and from address. NULL if a timeout occured
 * \param[in] arg The pointer passed in to jw_tracker_track.
 */
typedef void (*jw_tracker_cb_func)(jw_dom_node *result, void *arg);


#ifdef __cplusplus
extern "C"
{
#endif

/**
 * Create a tracker object with an associated event selector.
 *
 * This function can generate the following errors (set when returning false):
 * \li \c JW_ERR_NO_MEMORY Storage could not be allocated.
 *
 * \invariant selector != NULL
 * \invariant tracker != NULL
 * \param[in] selector The libevent selector to use for timeout tracking
 * \param[out] tracker The pointer to hold the initialized tracker
 * \param[out] err The error information (provide NULL to ignore)
 * \retval bool true if successful, false otherwise.
 */
JABBERWERX_API bool jw_tracker_create(struct event_base *selector,
                                      jw_tracker       **tracker,
                                      jw_err            *err);

/**
 * Destroy a tracker object.
 *
 * Note: Any outstanding responses being tracked will have their
 *       associated callbacks fired with a timeout condition.
 *
 * \invariant tracker != NULL
 * \param[in] tracker The tracker to free
 */
JABBERWERX_API void jw_tracker_destroy(jw_tracker *tracker);

/**
 * Track an IQ or an XDB response. Prepares the stanza to be sent,
 * then waits for the event handler returned from jw_tracker_get_callback() to
 * be fired with a matching response.  When a matching result or error is
 * detected, cb is called.  On timeout, cb is called with a NULL
 * result stanza.  If the outbound stanza does not have an id
 * attribute, one will be added.
 *
 * \b NOTE: The caller MUST send the stanza after this function has been called.
 * \b NOTE: The caller is responsible for arg cleanup. It will not be
 *       referenced by tracker once cb has been called.
 * \b NOTE: To disable timeouts entirely, pass 0 as timeout_sec
 *
 * This function can generate the following errors (set when returning false):
 * \li \c JW_ERR_NO_MEMORY Storage could not be allocated.
 * \li \c JW_ERR_INVALID_STATE stream is not connected
 * \li \c JW_ERR_OVERFLOW stream output buffer is full
 * \li \c JW_ERR_INVALID_ARG request is not a JW_DOM_TYPE_ELEMENT
 *
 * \invariant tracker != NULL
 * \invariant request != NULL
 * \invariant cb != NULL
 * \param[in] tracker The tracker to use
 * \param[in] request The request.  Any element you want, but IQ and
 *     XDB are likely the ones that make sense.
 * \param[in] cb the callback to call when the response is received or timeout
 * \param[in] arg A pointer to be passed in to cb
 * \param[in] timeout_sec The timeout period in seconds, or 0 to disable.
 * \param[out] err The error information (provide NULL to ignore)
 * \retval bool true if successful, false otherwise.
 */
JABBERWERX_API bool jw_tracker_track(jw_tracker        *tracker,
                                     jw_dom_node       *request,
                                     jw_tracker_cb_func cb,
                                     void              *arg,
                                     uint32_t           timeout_sec,
                                     jw_err            *err);

/**
 * Clear out all pending requests on the tracker, as if each request had timed
 * out.  To be used, for example, when the stream is disconnected.
 *
 * \invariant tracker != NULL
 * \param[in] tracker The tracker to clear
 */
JABBERWERX_API void jw_tracker_clear(jw_tracker *tracker);

/**
 * The callback to use to check inbound stanzas for responses.  When this
 * callback is bound to an event, the event MUST be one that sends a single
 * stanza as its data, and the tracker itself MUST be sent as the user data for
 * the event binding.
 *
 * EXAMPLE:
 * \code
 * jw_event_bind(jw_event_dispatcher_get_event(
 *                      dispatch, JW_CLIENT_EVENT_BEFORE_IQ_RECEIVED),
 *               jw_tracker_get_callback(),
 *               tracker,
 *               err);
 * \endcode
 *
 * \retval jw_event_notify_callback The callback function to bind.
 */
JABBERWERX_API jw_event_notify_callback jw_tracker_get_callback();

#ifdef __cplusplus
}
#endif

#endif /* JABBERWERX_TRACKER_H */
