/**
 * \file
 * \brief
 * Functions and data structures for client
 *
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

#ifndef JABBERWERX_CLIENT_H
#define JABBERWERX_CLIENT_H

#include "jid.h"
#include "tracker.h"
#include "stream.h"
#include "util/workq.h"


/**
 * Configuration option to specify the user JID. The value for this option
 * MUST be a UTF-8 encoded string (char *).
 */
#define JW_CLIENT_CONFIG_USERJID "userjid"
/**
 * Configuration option to specify the user password. The value for this option
 * MUST be a UTF-8 encoded string (char *).
 */
#define JW_CLIENT_CONFIG_USERPW "userpassword"
/**
 * Configuration option to specify the stream type. The value for this option
 * MUST be either JW_CLIENT_CONFIG_STREAM_TYPE_BOSH or
 * JW_CLIENT_CONFIG_STREAM_TYPE_SOCKET (default).
 */
#define JW_CLIENT_CONFIG_STREAM_TYPE "streamtype"
/**
 * Configuration option to specify the JID context to use (OPTIONAL). The value
 * for this option MUST be a jw_jid_ctx; if not specified, a new context will be
 * created and used.
 */
#define JW_CLIENT_CONFIG_JID_CONTEXT "jidcontext"
/**
 * Configuration option to specify whether stream management (specified in
 * XEP-0198) is enabled (OPTIONAL).  The value for this option MUST be a
 * (bool)(uintptr_t), and defaults to true.
 */
#define JW_CLIENT_CONFIG_SM_ENABLED "sm_enabled"
/**
 * Configuration option to specify whether stream resumption (specified in
 * XEP-0198) is enabled (OPTIONAL).  The value for this option MUST be a
 * (bool)(uintptr_t), and defaults to true.  If the value of
 * JW_CLIENT_CONFIG_SM_ENABLED is false, then this option is ignored.
 */
#define JW_CLIENT_CONFIG_SM_RESUME_ENABLED "sm_resume_enabled"
/**
 * Configuration option to specify the maximum time (in seconds) the client
 * would like the server to wait before it purges state required for stream
 * resumption (specified in XEP-0198) (OPTIONAL). The value for this option MUST
 * be a UTF-8 encoded integer string (e.g. "30").  If not specified, the server
 * chooses a default.  Note that even if this option is specified, the server is
 * not guaranteed to respect the value.
 */
#define JW_CLIENT_CONFIG_SM_RESUME_TIMEOUT_SECONDS "sm_resume_timeout"
/**
 * Configuration option to specify the upper bound (non-inclusive) for the
 * number of stanzas that can go unacknowledged by the server before the client
 * requests an acknowledgment (OPTIONAL). The value for this option MUST be a
 * (uint32_t)(uintptr_t).  If not specified, or specified as the value 0, a
 * default value of 5 is used.  Note that this is just a threshold for
 * requesting an acknowledgment.  No errors or throttling will occur if the
 * server does not respond with an acknowledgment in a timely manner.  Be aware
 * that when resuming is enabled, the more requests that go unacknowledged by
 * the server, the more memory the client must use to store the unacknowledged
 * stanzas.
 */
#define JW_CLIENT_CONFIG_SM_ACK_REQUEST_THRESHOLD "sm_ack_request_threshold"
/**
 * Configuration option to specify the maximum number of seconds (and optional
 * milliseconds) to wait before the client requests an acknowledgment from the
 * server for any unacknowledged stanzas (OPTIONAL). The value for this option
 * MUST be a UTF-8 encoded string (char *) representing a real number where the
 * whole number part specifies seconds and the fractional part milliseconds (for
 * example "30" or "30.0"). If not specified, or specified as the value less
 * than or equal to 0, a default value of 30 seconds is used.
 *
 * Note that this is just a threshold for requesting an acknowledgment.
 * No errors or throttling will occur if the server does not respond with an
 * acknowledgment in a timely manner.  Moreover, a request is only sent if there
 * are outstanding stanzas to acknowledge.  It is not a keepalive mechanism (see
 * JW_STREAM_CONFIG_KEEPALIVE_SECONDS).  This option is useful for ensuring
 * acknowlegments are requested for outstanding stanzas when the stanza send
 * rate is so low that the JW_CLIENT_CONFIG_SM_ACK_REQUEST_THRESHOLD is not
 * often crossed.  This reduces the number of stanzas a client may send at
 * session resumption that were in fact already received by the remote endpoint
 * but not yet acknowledged by the server.
 */
#define JW_CLIENT_CONFIG_SM_ACK_REQUEST_THRESHOLD_SECONDS \
        "sm_ack_request_threshold_seconds"
/**
 * Configuration option to specify the base time a client will wait between
 * connections (OPTIONAL). This configuration option can be used to disable
 * reconnection.
 *
 * The value for this option MUST be a UTF-8 encoded string (char *)
 * representing a real number where the whole number part specifies seconds and
 * the fractional part specifies milliseconds. For example "30.500" would define
 * a wait time of 30 1/2 seconds.
 *
 * Note most users should simply use whole seconds (e.g. "10").
 *
 * This is an approximate time where a random delta is added or
 * subtracted from the base for each connection attempt. If no value is
 * specified a default of "10" seconds is used. If a value less than or equal to
 * 0 is specified reconnection is disabled.
 *
 * As more attempts are made, a multiple of the base time will be used, thus
 * lengthening the time between attempts (a commonly used network algorithm.)
 */
#define JW_CLIENT_CONFIG_RECONNECT_BASE_COUNTDOWN "client_reconnect_countdown"
/**
 * Configuration option to specify the SASL factory to use for authentication
 * negotiation (OPTIONAL). The value for this option MUST be a jw_sasl_factory;
 * if not specified, a new factory with default, Mandatory-to-Implement SASL
 * mechanisms will be created and used.
 */
#define JW_CLIENT_CONFIG_SASL_FACTORY "client_sasl_factory"

/**
 * Value to specify socket for JW_CLIENT_CONFIG_STREAM_TYPE
 */
#define JW_CLIENT_CONFIG_STREAM_TYPE_SOCKET "socket"
/**
 * Value to specify bosh for JW_CLIENT_CONFIG_STREAM_TYPE
 */
#define JW_CLIENT_CONFIG_STREAM_TYPE_BOSH "bosh"

/**
 * The "clientStatusChanged" event, as documented in <a
 * href='../../events.rst'>Events</a>.
 */
#define JW_CLIENT_EVENT_STATUSCHANGED "clientStatusChanged"
/**
 * The "clientConnected" event, as documented in <a
 * href='../../events.rst'>Events</a>.
 */
#define JW_CLIENT_EVENT_CONNECTED "clientConnected"
/**
 * The "clientDisconnected" event, as documented in <a
 * href='../../events.rst'>Events</a>.
 */
#define JW_CLIENT_EVENT_DISCONNECTED "clientDisconnected"
/**
 * The "sessionPaused" event, as documented in <a
 * href='../../events.rst'>Events</a>.
 */
#define JW_CLIENT_EVENT_SESSION_PAUSED "clientSessionPaused"
/**
 * The "sessionResumed" event, as documented in <a
 * href='../../events.rst'>Events</a>.
 */
#define JW_CLIENT_EVENT_SESSION_RESUMED "clientSessionResumed"
/**
 * The "clientDestroyed" event, as documented in <a
 * href='../../events.rst'>Events</a>.
 */
#define JW_CLIENT_EVENT_DESTROYED "clientDestroyed"

/**
 * The "beforeIqReceived" event, as documented in <a
 * href='../../events.rst'>Events</a>.
 */
#define JW_CLIENT_EVENT_BEFORE_IQ_RECEIVED "beforeIqReceived"
/**
 * The "iqReceived" event, as documented in <a
 * href='../../events.rst'>Events</a>.
 */
#define JW_CLIENT_EVENT_IQ_RECEIVED "iqReceived"
/**
 * The "afterIqReceived" event, as documented in <a
 * href='../../events.rst'>Events</a>.
 */
#define JW_CLIENT_EVENT_AFTER_IQ_RECEIVED "afterIqReceived"

/**
 * The "beforeIqSent" event, as documented in <a
 * href='../../events.rst'>Events</a>.
 */
#define JW_CLIENT_EVENT_BEFORE_IQ_SENT "beforeIqSent"
/**
 * The "iqSent" event, as documented in <a
 * href='../../events.rst'>Events</a>.
 */
#define JW_CLIENT_EVENT_IQ_SENT "iqSent"

/**
 * The "beforePresenceReceived" event, as documented in <a
 * href='../../events.rst'>Events</a>.
 */
#define JW_CLIENT_EVENT_BEFORE_PRESENCE_RECEIVED "beforePresenceReceived"
/**
 * The "presenceReceived" event, as documented in <a
 * href='../../events.rst'>Events</a>.
 */
#define JW_CLIENT_EVENT_PRESENCE_RECEIVED "presenceReceived"
/**
 * The "afterPresenceReceived" event, as documented in <a
 * href='../../events.rst'>Events</a>.
 */
#define JW_CLIENT_EVENT_AFTER_PRESENCE_RECEIVED "afterPresenceReceived"

/**
 * The "beforePresenceSent" event, as documented in <a
 * href='../../events.rst'>Events</a>.
 */
#define JW_CLIENT_EVENT_BEFORE_PRESENCE_SENT "beforePresenceSent"
/**
 * The "presenceSent" event, as documented in <a
 * href='../../events.rst'>Events</a>.
 */
#define JW_CLIENT_EVENT_PRESENCE_SENT "presenceSent"

/**
 * The "beforeMessageReceived" event, as documented in <a
 * href='../../events.rst'>Events</a>.
 */
#define JW_CLIENT_EVENT_BEFORE_MESSAGE_RECEIVED "beforeMessageReceived"
/**
 * The "messageReceived" event, as documented in <a
 * href='../../events.rst'>Events</a>.
 */
#define JW_CLIENT_EVENT_MESSAGE_RECEIVED "messageReceived"
/**
 * The "afterMessageReceived" event, as documented in <a
 * href='../../events.rst'>Events</a>.
 */
#define JW_CLIENT_EVENT_AFTER_MESSAGE_RECEIVED "afterMessageReceived"

/**
 * The "beforeMessageSent" event, as documented in <a
 * href='../../events.rst'>Events</a>.
 */
#define JW_CLIENT_EVENT_BEFORE_MESSAGE_SENT "beforeMessageSent"
/**
 * The "messageSent" event, as documented in <a
 * href='../../events.rst'>Events</a>.
 */
#define JW_CLIENT_EVENT_MESSAGE_SENT "messageSent"

/**
 * The "reconnectStatus" event, as documented in <a
 * href='../../events.rst'>Events</a>.
 */
#define JW_CLIENT_EVENT_RECONNECT_STATUSCHANGED "reconnectStatusChanged"


/**
 * Enumeration of client status type
 */
typedef enum
{
    JW_CLIENT_DISCONNECTED = 0,
    JW_CLIENT_CONNECTING,
    JW_CLIENT_CONNECTED,
    JW_CLIENT_DISCONNECTING
} jw_client_statustype;

/**
 * Enumeration of client reconnecting status type
 *
 * Reconnection status will be one of the following:
 * \li JW_CLIENT_RECONNECT_PENDING if reconnection is enabled, there has been a
 * prior successful connection, and client disconnection was forced by an error.
 *
 * \li JW_CLIENT_RECONNECT_STARTING if a reconnection attempt is currently being
 * made.
 *
 * \li JW_CLIENT_RECONNECT_CANCELED if reconnection is disabled, there has not
 * been a prior successful connection, or the client was disconnected normally
 * through a call to jw_client_disconnect.
 */
typedef enum
{
    JW_CLIENT_RECONNECT_CANCELED = 0, // reconnect can not occur
    JW_CLIENT_RECONNECT_PENDING,      // reconnect attempt when possible
    JW_CLIENT_RECONNECT_STARTING      // connection is being attempted
} jw_client_reconnect_statustype;


/** An instance of a client. */
typedef struct _jw_client jw_client;

/** An instance of a client status. */
typedef struct _jw_client_status jw_client_status;

/** An instance of a reconnect status */
typedef struct _jw_client_reconnect_status jw_client_reconnect_status;


#ifdef __cplusplus
extern "C"
{
#endif

/**
 * Create a client.
 *
 * This function can generate the following errors (set when returning false):
 * \li \c JW_ERR_NO_MEMORY if the client could not be allocated, or if the
 * stream could not be allocated.
 *
 * \invariant workq != NULL
 * \invariant client != NULL
 * \param[in] workq the workq to use for triggering events asynchronously
 * \param[out] client The newly created client.
 * \param[out] err The error information (provide NULL to ignore).
 * \retval bool true if the client was created successfully.
 */
JABBERWERX_API bool jw_client_create(jw_workq   *workq,
                                     jw_client **client,
                                     jw_err    *err);

/**
 * Destroy the client.
 *
 * \b NOTE: This is an asynchronous operation and requires the libevent event
 * loop to run in order to complete.
 *
 * \b NOTE: This function does not release the config, if any were still
 * applied. The API user is expected to release the config hashtable manually
 * when/after the JW_CLIENT_EVENT_DESTROYED event is fired.
 *
 * \invariant client != NULL
 * \param[in] client The client to clean up.
 */
JABBERWERX_API void jw_client_destroy(jw_client *client);

/**
 * Connects the client.
 *
 * This function connects the client. It begins the process of connecting to an
 * XMPP remote endpoint. It may return before the client is ready for use;
 * bind a callback to the "clientConnected" event to know when a client is
 * fully connected and ready for use. It is RECOMMENDED to also bind a callback
 * to the "clientDisconnected" event to be informed of errors. The API user can
 * also bind a callback to the "clientStatusChanged" event to be informed of
 * any client status change.
 *
 * The config MUST have values for the following:
 * \li JW_CLIENT_CONFIG_USERJID
 * \li JW_STREAM_CONFIG_SELECTOR
 *
 * The value of JW_CLIENT_USERJID MUST contain a bare JID
 * (localpart\@domainpart) and MAY be a full jid
 * (localpart\@domainpart/resourcepart). If a full JID is provided the client
 * will attempt to use the resource part during connection, subject to JID
 * binding.
 *
 * For bosh streams, i.e. when JW_CLIENT_CONFIG_STREAM_TYPE is set to "bosh",
 * the following items must additionally be set:
 * \li JW_STREAM_CONFIG_URI
 *
 * The config must also have whichever items are required for the chosen SASL
 * authentication mechanism.  For example, for SASL PLAIN,
 * JW_CLIENT_CONFIG_USERPW must be populated.
 *
 * The following config values are always enforced:
 * \li JW_STREAM_CONFIG_DOMAIN is the domainpart of JW_CLIENT_CONFIG_USERJID
 * \li JW_STREAM_CONFIG_NAMESPACE is "jabber:client"
 *
 * The following default values will be used if not specified:
 * \li JW_CLIENT_CONFIG_STREAM_TYPE defaults to
 * JW_CLIENT_CONFIG_STREAM_TYPE_SOCKET
 * \li JW_STREAM_CONFIG_HOST defaults to JW_STREAM_CONFIG_DOMAIN
 * \li JW_STREAM_CONFIG_PORT defaults to "5222"
 * \li JW_CLIENT_CONFIG_SM_ENABLED defaults to true
 * \li JW_CLIENT_CONFIG_SM_RESUME_ENABLED defaults to true
 * \li JW_CLIENT_CONFIG_RECONNECT_BASE_COUNTDOWN defaults to "10" seconds
 *
 * This function can generate the following errors (set when returning false):
 * \li \c JW_ERR_NO_MEMORY if the connection objects could not be allocated
 * \li \c JW_ERR_INVALID_STATE if the client is not in a disconnected status
 * \li \c JW_ERR_INVALID_ARG if required fields in the config are missing
 *                           or invalid
 *
 * \b NOTE: Due to the asynchronous nature of streams, this function may return
 * true but the operation fails. Such failures will be reported via the
 * "clientDisconnected" event.
 *
 * \b NOTE: This function does not take ownership of the config. The API
 * user is expected to release the config hashtable either within the callback
 * for the "clientDestroyed" event or sometime after the event has fired.
 *
 * \invariant client != NULL
 * \invariant config != NULL
 * \param[in] client The client to connect.
 * \param[in] config The collection of configuration options for the client.
 * \param[out] err The error information (provide NULL to ignore)
 * \retval bool true if successful, false otherwise.
 */
JABBERWERX_API bool jw_client_connect(jw_client *client,
                                      jw_htable *config,
                                      jw_err    *err);

/**
 * Disconnect the client.
 *
 * \b NOTE: This function may be called to cancel reconnection attempts.
 *    If the client is disconnected and not attempting reconnect this function
 *       just returns immediately.
 *    if a reconnect attempt is scheduled and the client's state is disconnected
 *       the reconnection attempt is canceled and a reconnectStatus event is
 *       fired with the JW_CLIENT_RECONNECT_CANCELED state.
 *    if a reconnect (or user requested connection) is underway (client's status
 *       is "connecting"), this function returns an invalid state error.
 *    if the client is connected this function disconnects and prevents
 *       any reconnection attempts.
 *
 * \invariant client != NULL
 * \param[in] client The client to close.
 * \param[in] disconnect_reason The error that precipitated this disconnection
 */
JABBERWERX_API void jw_client_disconnect(jw_client *client,
                                         jw_errcode disconnect_reason);

/**
 * Gets the workq associated with the client.
 *
 * \invariant client != NULL
 * \param[in] client The client.
 * \retval jw_workq* The associated workq.
 */
JABBERWERX_API jw_workq* jw_client_get_workq(jw_client *client);

/**
 * Gets the selector associated with the client.
 *
 * \invariant client != NULL
 * \param[in] client The client.
 * \retval struct event_base* The associated selector.
 */
JABBERWERX_API struct event_base* jw_client_get_selector(jw_client *client);

/**
 * Retrieves the current status of the client.
 *
 * \invariant client != NULL
 * \param[in] client The client.
 * \retval jw_client_statustype The client's current status
 */
JABBERWERX_API jw_client_statustype jw_client_get_status(jw_client *client);

/**
 * Retrieves the config for the client.
 *
 * \b Note: This function will return NULL if a config is not available, for
 * example before jw_client_connect() is called or after jw_client_disconnect()
 * is called.  In particular, take note that this function will return NULL
 * during the clientDestroyed event, so if you wish to destroy the config during
 * that event, you must pass it as the opaque argument or have some other way to
 * retrieve it.
 *
 * \invariant client != NULL
 * \param[in] client The client.
 * \retval jw_htable The client's configuration table.
 */
JABBERWERX_API jw_htable *jw_client_get_config(jw_client *client);

/**
 * Retrieves the currently connected jw_jid
 *
 * This function returns a reference to the currently connected jid. A jw_jid
 * will only be returned if jw_client_is_connected would return true. For all
 * other client states this function returns <tt>NULL</tt>.
 *
 * \b Note: The jw_jid reference is owned by jw_client and may be destroyed at
 * any time.
 *
 * \invariant client != NULL
 * \param[in] client The client.
 * \retval jw_jid The client's jid or NULL if not connected.
 */
JABBERWERX_API jw_jid *jw_client_get_jid(jw_client *client);

/**
 * Determines if the client is connected, allowing stanzas to be sent and
 * received.
 *
 * \invariant client != NULL
 * \param[in] client The client.
 * \retval bool <tt>true</tt> if client is connected
 */
JABBERWERX_API bool jw_client_is_connected(jw_client *client);

/**
 * Determines if the client has scheduled or is attempting a reconnection.
 *
 * This function will return true if the client is disconnected but a
 * reconnection attempt is scheduled to be attempted, or if the client is
 * attempting a reconnection but not yet connected.
 * This function will return false if the client is connected or no reconnection
 * attempt is scheduled.
 *
 * \invariant client != NULL
 * \param[in] client The client.
 * \retval bool <tt>true</tt> if client is or will be attempting to reconnect.
 */
JABBERWERX_API bool jw_client_is_reconnect_pending(jw_client *client);

/**
 * Get a client event.  Returns the event on success and NULL if event is not
 * found.
 * The memory allocated for the event will continue to be owned by the client.
 *
 * \invariant client != NULL
 * \invariant name != NULL
 * \invariant *name != '\\0'
 * \param[in] client The client owning the event dispatcher.
 * \param[in] name The name of the event.
 * \retval jw_event The found event or NULL if it does not exist.
 */
JABBERWERX_API jw_event *jw_client_event(jw_client *client,
                                        const char *name);

/**
 * Get previous client status
 *
 * \b NOTE: The client status API is not stable; changes may happen in future
 * releases.
 *
 * \invariant status != NULL
 * \param[in] status The client status.
 * \retval jw_client_statustype The previous client status.
 */
JABBERWERX_API jw_client_statustype jw_client_status_get_previous(
                                                    jw_client_status *status);

/**
 * Get current client status
 *
 * \b NOTE: The client status API is not stable; changes may happen in future
 * releases.
 *
 * \invariant status != NULL
 * \param[in] status The client status.
 * \retval jw_client_statustype The current client status.
 */
JABBERWERX_API jw_client_statustype jw_client_status_get_next(
                                                    jw_client_status *status);

/**
 * Get client status error DOM.
 *
 * \b NOTE: The client status API is not stable; changes may happen in future
 * releases.
 *
 * \invariant status != NULL
 * \param[in] status The client status.
 * \retval jw_dom_node The client status error DOM.
 */
JABBERWERX_API jw_dom_node *jw_client_status_get_error(
                                                    jw_client_status *status);

/**
 * Get the client status reconnecting flag.
 *
 * This function will return <tt>true</tt>
 *      if state is not connected or disconnected and a reconnection attempt
 *          is underway.
 *      if state is disconnected and a reconnect is pending.
 *
 * \b NOTE: The client status API is not stable; changes may happen in future
 * releases.
 *
 * \invariant status != NULL
 * \param[in] status The client status.
 * \retval boolean <tt>true</tt> if a reconnection attempt is underway or pending
 */
JABBERWERX_API bool jw_client_status_is_reconnect(jw_client_status *status);

/**
 * Get the reconnect status reconnecting flag.
 *
 * This function is an accessor for the JW_CLIENT_RECONNECT_STATUS event's
 * jw_client_reconnect_status data object. It returns the reconnect status
 * type.
 *
 * \b NOTE: The client status API is not stable; changes may happen in future
 * releases.
 *
 * \invariant status != NULL
 * \param[in] status The client status.
 * \retval jw_client_reconnect_statustype The reconnect status
 */
JABBERWERX_API jw_client_reconnect_statustype
jw_client_reconnect_get_status(jw_client_reconnect_status *status);

/**
 * Get the reconnect status countdown.
 *
 * This function is an accessor for the JW_CLIENT_RECONNECT_STATUS event's
 * jw_client_reconnect_status data object. It returns the countdown in seconds
 * to the next reconnection attempt. This value is only set when the
 * corresponding status is JW_CLIENT_RECONNECT_PENDING and is 0 in other states.
 *
 * \b NOTE: The client status API is not stable; changes may happen in future
 * releases.
 *
 * \invariant status != NULL
 * \param[in] status The client status.
 * \retval uint32_t The number of seconds until a reconnection attempt or 0.
 */
JABBERWERX_API uint32_t
jw_client_reconnect_get_countdown(jw_client_reconnect_status *status);

/**
 * Get the reconnect status attempts counter
 *
 * This function is an accessor for the JW_CLIENT_RECONNECT_STATUS event's
 * jw_client_reconnect_status data object. It returns the number of previously
 * failed attempts reconnection attempts.
 *
 * \b NOTE: The client status API is not stable; changes may happen in future
 * releases.
 *
 * \invariant status != NULL
 * \param[in] status The client status.
 * \retval uint32_t  the number of previously failed attempts.
 */
JABBERWERX_API uint32_t
jw_client_reconnect_get_attempts(jw_client_reconnect_status *status);

/**
 * Sends a stanza to the XMPP server.
 *
 * \b NOTE: The client takes ownership of the stanza's memory, regardless of
 * whether it is successfully sent. The caller MUST NOT destroy the stanza.  If
 * you need to access the stanza or its context after this call, ensure you
 * first call jw_dom_context_retain() to increment the context refcount.
 *
 * This function can generate the following errors (set when returning false):
 * \li \c JW_ERR_NO_MEMORY if memory to serialize the DOM could not be allocated
 * \li \c JW_ERR_INVALID_STATE if the client is not in a connected state
 * \li \c JW_ERR_INVALID_ARG if the localname of the stanza is not one of "iq",
 *                           "message", or "presence"
 *
 * \b NOTE: Due to the asynchronous nature of streams, this function may return
 * true but the operation fails. Such failures will be reported via the
 * "disconnected" event.
 *
 * \invariant client != NULL
 * \invariant stanza != NULL
 * \param[in] client The client context.
 * \param[in] stanza The stanza to send.
 * \param[out] err The error information (provide NULL to ignore)
 * \retval bool true if successful, false otherwise.
 */
JABBERWERX_API bool jw_client_send_stanza(jw_client   *client,
                                          jw_dom_node *stanza,
                                          jw_err      *err);

/**
 * Send an IQ request, waiting for the corresponding response, error, or
 * timeout.
 *
 * When a matching result is detected, cb is called.  On timeout, cb is called
 * with a NULL result stanza.  If the outbound iq stanza does not have an id
 * attribute, one will be added.
 *
 * \b NOTE: The client takes ownership of the stanza's memory, regardless of
 * whether it is successfully sent. The caller MUST NOT destroy the stanza.  If
 * you need to access the stanza or its context after this call, ensure you
 * first call jw_dom_context_retain() to increment the context refcount.
 * \b NOTE: The caller is responsible for user_data cleanup. It will not be
 * referenced by tracker once cb has been called.
 * \b NOTE: To disable timeouts entirely, pass 0 as timeout_sec
 *
 * This function can generate the following errors (set when returning false):
 * \li \c JW_ERR_NO_MEMORY if storage could not be allocated.
 * \li \c JW_ERR_NO_MEMORY if memory to serialize the DOM could not be allocated
 * \li \c JW_ERR_INVALID_STATE if the client is not in a connected state
 * \li \c JW_ERR_OVERFLOW stream output buffer is full
 * \li \c JW_ERR_INVALID_ARG request is not a JW_DOM_TYPE_ELEMENT with name "iq"
 *
 * \invariant client != NULL
 * \invariant stanza != NULL
 * \invariant cb != NULL
 * \param[in] client The client context
 * \param[in] iq The request.  MUST be an IQ.
 * \param[in] cb the callback to call when the response is received or timeout
 * \param[in] user_data A pointer to be passed in to cb
 * \param[in] timeout_sec The timeout period in seconds, or 0 to disable.
 * \param[out] err The error information (provide NULL to ignore)
 * \retval bool true if successful, false otherwise.
 */
JABBERWERX_API bool jw_client_track_iq(jw_client         *client,
                                       jw_dom_node       *iq,
                                       jw_tracker_cb_func cb,
                                       void              *user_data,
                                       uint32_t           timeout_sec,
                                       jw_err            *err);

#ifdef __cplusplus
}
#endif

#endif  /* JABBERWERX_CLIENT_H */
