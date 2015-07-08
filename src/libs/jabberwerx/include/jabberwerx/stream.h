/**
 * \file
 * \brief
 * Functions and data structures for Streams of XML data over a data transport,
 * such as a TCP stream.
 *
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

#ifndef JABBERWERX_STREAM_H
#define JABBERWERX_STREAM_H

#include <event2/bufferevent.h>
#include "util/htable.h"
#include "eventing.h"
#include "dom.h"


/**
 * Configuration option to specify the XMPP namespace. The value for this
 * option MUST be a UTF-8 encoded string (char *).
 */
#define JW_STREAM_CONFIG_NAMESPACE "namespace"
/**
 * Configuration option to specify the XMPP domain. The value for this option
 * MUST be a UTF-8 encoded string (char *).
 */
#define JW_STREAM_CONFIG_DOMAIN "domain"
/**
 * Configuration option to specify the remote host IP address. The value for
 * this option MUST be a UTF-8 encoded string (char *).  If not specified,
 * it defaults to the value of JW_STREAM_CONFIG_DOMAIN.
 */
#define JW_STREAM_CONFIG_HOST "host"
/**
 * Configuration option to specify the remote port for socket connections.  The
 * value for this option MUST be a UTF-8 encoded string (char *).  BOSH
 * connections ignore this config option and instead read the port specifier
 * from the JW_STREAM_CONFIG_URI option.  This configuration element is required
 * for socket connections unless JW_STREAM_CONFIG_BUFFEREVENT is specified.
 */
#define JW_STREAM_CONFIG_PORT "port"
/**
 * Configuration option to specify the event_base selector. The value for this
 * option MUST be a struct event_base*.  If not specified, the selector is
 * taken from the jw_workq specified in JW_STREAM_CONFIG_WORKQ.
 */
#define JW_STREAM_CONFIG_SELECTOR JW_WORKQ_CONFIG_SELECTOR
/**
 * Configuration option to specify the URI for BOSH. The value for this MUST
 * be a UTF-8 encoded string (char *).
 */
#define JW_STREAM_CONFIG_URI "uri"
/**
 * Optional configuration option to specify a label for log messages related to
 * this stream instance. The value MUST be a UTF-8 encoded string (char *).
 */
#define JW_STREAM_CONFIG_LOG_LABEL "loglabel"
/**
 * Configuration option to specify the receive/send queue size for socket
 * streams.  Larger queues allow more stanzas to be sent in quick succession,
 * such as when the stream is resuming after a network interruption and multiple
 * stanzas need to be resent to the server.  The value for this option MUST be a
 * (size_t)(uintptr_t) value.  If not specified, or specified as the value 0,
 *  a default value of 500 is used.
 */
#define JW_STREAM_CONFIG_QUEUE_SIZE "queuesize"
/**
 * Configuration option to specify the number of seconds (and optional
 * milliseconds) of inactivity to allow before a keepalive action is taken.  For
 * socket connections, a whitespace keepalive packet will be sent.  For bosh
 * connections, an idle HTTP connection to the server will be closed and another
 * will be established.  The value for this option MUST be a UTF-8 encoded
 * string (char *) representing a real number where the whole number part
 * specifies seconds and the fractional part milliseconds (for example "30" or
 * "30.0"). If not specified, or specified as the value less than or equal to 0,
 * a default value of 270 seconds is used.
 */
#define JW_STREAM_CONFIG_KEEPALIVE_SECONDS "keepalive_seconds"
/**
 * Configuration option to specify the name of the file that contains the
 * certificate chain to use for authorization (OPTIONAL).  The certificates must
 * be in PEM format and must be sorted starting with the client certificate,
 * followed by intermediate CA certificates if applicable, and ending at the
 * highest level (root) CA. The value for this option MUST be a string that
 * represents the path to the certificate chain file.  Note this this option is
 * currently only implemented for socket connections.
 */
#define JW_STREAM_CONFIG_TLS_CERTIFICATE_CHAIN_FILENAME "stream_cert_chain_file"
/**
 * Configuration option to specify the name of the file that contains the
 * private key (in PEM format) to use for authorization (OPTIONAL). The value
 * for this option MUST be a string that represents the path to the private key
 * file.  Note this this option is currently only implemented for socket
 * connections.
 */
#define JW_STREAM_CONFIG_TLS_PRIVATE_KEY_FILENAME "stream_private_key_file"
/**
 * Configuration option to provide a socket stream with a custom bufferevent
 * (struct bufferevent *). The bufferevent must already be connected
 * (BEV_EVENT_CONNECTED), and hence no DNS resolution will happen. Also, the
 * bufferevent must be assigned to the event_base of the stream. The user is
 * responsible for freeing the bufferevent (via bufferevent_free()). BOSH
 * connections ignore this config option.
 */
#define JW_STREAM_CONFIG_BUFFEREVENT "socket_bufferevent"

/**
 * The "streamOpened" event, as documented in <a
 * href='../../events.rst'>Events</a>.
 */
#define JW_STREAM_EVENT_OPENED "streamOpened"
/**
 * The "streamClosed" event, as documented in <a
 * href='../../events.rst'>Events</a>.
 */
#define JW_STREAM_EVENT_CLOSED "streamClosed"
/**
 * The "streamElementsReceived" event, as documented in <a
 * href='../../events.rst'>Events</a>.
 */
#define JW_STREAM_EVENT_ELEMRECV "streamElementsReceived"
/**
 * The "streamElementsSent" event, as documented in <a
 * href='../../events.rst'>Events</a>.
 */
#define JW_STREAM_EVENT_ELEMSENT "streamElementsSent"
/**
 * The "streamDestroyed" event, as documented in <a
 * href='../../events.rst'>Events</a>.
 */
#define JW_STREAM_EVENT_DESTROYED "streamDestroyed"


/** An instance of a stream. */
typedef struct _jw_stream jw_stream;


#ifdef __cplusplus
extern "C"
{
#endif

/**
 * Create a BOSH stream.
 *
 * This function can generate the following errors (set when returning false):
 * \li \c JW_ERR_NO_MEMORY if the stream could not be allocated, if the
 * event dispatcher could not be allocated, or the individual events could not
 * be allocated.
 * \li \c JW_ERR_NOT_IMPLEMENTED if BOSH support has not been compiled into this
 * distributable.
 *
 * \invariant workq != NULL
 * \invariant stream != NULL
 * \param[in] workq the workq to use for triggering events asynchronously
 * \param[out] stream The newly created stream.
 * \param[out] err The error information (provide NULL to ignore)
 * \retval bool true if the stream was created successfully.
 */
JABBERWERX_API bool jw_stream_bosh_create(jw_workq   *workq,
                                          jw_stream **stream,
                                          jw_err    *err);

/**
 * Create a long-lived TCP stream.
 *
 * This function can generate the following errors (set when returning false):
 * \li \c JW_ERR_NO_MEMORY if the stream could not be allocated, if the
 * event dispatcher could not be allocated, or the individual events could not
 * be allocated.
 *
 * \invariant workq != NULL
 * \invariant stream != NULL
 * \param[in] workq the workq to use for triggering events asynchronously
 * \param[out] stream The newly created stream.
 * \param[out] err The error information (provide NULL to ignore)
 * \retval bool true if the stream was created successfully.
 */
JABBERWERX_API bool jw_stream_socket_create(jw_workq   *workq,
                                            jw_stream **stream,
                                            jw_err    *err);

/**
 * Destroy the stream.
 *
 * \b NOTE: This is an asynchronous operation and requires the libevent event
 * loop to run in order to complete.
 *
 * \b NOTE: This function does not release the config, if any were still
 * applied. The API user is expected to release the config hashtable manually
 * when/after the JW_STREAM_EVENT_DESTROYED event is fired.
 * 
 * \invariant stream != NULL
 * \param[in] stream The jw_stream to clean up.
 */
JABBERWERX_API void jw_stream_destroy(jw_stream *stream);

/**
 * Opens the stream. This function begins the process of connecting to an
 * XMPP remote endpoint.  It may return before the stream is ready for use;
 * bind a callback to the "streamOpened" event to know when a stream is
 * fully open and ready for use.  It is RECOMMENDED to also bind a callback
 * to the "streamClosed" event to be informed of errors.
 *
 * The config MUST have values for the following:
 * \li JW_STREAM_CONFIG_NAMESPACE
 * \li JW_STREAM_CONFIG_DOMAIN
 *
 * For bosh streams, the following items must additionally be set:
 * \li JW_STREAM_CONFIG_URI
 * 
 * The following config values are always enforced:
 * \li JW_STREAM_CONFIG_SELECTOR is the selector from the workq passed to the
 * create() function
 *
 * This function can generate the following errors (set when returning false):
 * \li \c JW_ERR_NO_MEMORY if the connection objects could not be allocated
 * \li \c JW_ERR_INVALID_STATE if the stream is not in a closed state
 * \li \c JW_ERR_INVALID_ARG if required fields in the config are missing
 *                           or invalid
 *
 * \b NOTE: Due to the asynchronous nature of streams, this function may return
 * true but the operation fails. Such failures will be reported via the
 * "streamClosed" event.
 *
 * \b NOTE: This function does not take ownership of the config. The API
 * user is expected to release the config hashtable either within the callback
 * for the "streamDestroyed" event or sometime after the event has fired.
 *
 * \invariant stream != NULL
 * \invariant config != NULL
 * \param[in] stream The stream to open.
 * \param[in] config The collection of configuration options for the stream.
 * \param[out] err The error information (provide NULL to ignore)
 * \retval bool true if successful, false otherwise.
 */
JABBERWERX_API bool jw_stream_open(jw_stream *stream,
                                   jw_htable *config,
                                   jw_err    *err);

/**
 * Reopens the stream. This function resets all XML information and sends a new
 * &lt;stream:stream&gt; opening tag. It may return before the stream is again
 * ready for use; bind a callback to the "streamOpened" event to know when a
 * stream is fully open and ready for use. It is RECOMMENDED to also bind a
 * callback to the "streamClosed" event to be informed of errors.
 *
 * This function can generate the following errors (set when returning false):
 * \li \c JW_ERR_INVALID_STATE if the stream is not in a ready state
 *
 * \b NOTE: Due to the asynchronous nature of streams, this function may return
 * true but the operation fails. Such failures will be reported via the
 * "streamClosed" event.
 *
 * \invariant stream != NULL
 * \param[in] stream The stream to reopen.
 * \param[out] err The error information (provide NULL to ignore)
 * \retval bool true if successful, false otherwise.
 */
JABBERWERX_API bool jw_stream_reopen(jw_stream *stream,
                                     jw_err    *err);

/**
 * Sends a DOM through the stream.
 *
 * \b NOTE: The stream takes ownership of the stanza's memory, regardless of
 * whether it is successfully sent. The caller MUST NOT destroy the stanza.  If
 * you need to access the stanza or its context after this call, ensure you
 * first call jw_dom_context_retain() to increment the context refcount.
 *
 * This function can generate the following errors (set when returning false):
 * \li \c JW_ERR_NO_MEMORY if memory to serialize the DOM could not be allocated
 * \li \c JW_ERR_INVALID_STATE if the stream is not open
 *
 * \b NOTE: Due to the asynchronous nature of streams, this function may return
 * true but the operation fails. Such failures will be reported via the
 * "streamClosed" event.
 *
 * \invariant stream != NULL
 * \invariant dom != NULL
 * \param[in] stream The stream to use.
 * \param[in] dom The dom to send.
 * \param[out] err The error information (provide NULL to ignore)
 * \retval bool true if successful, false otherwise.
 */
JABBERWERX_API bool jw_stream_send(jw_stream   *stream,
                                   jw_dom_node *dom,
                                   jw_err      *err);

/**
 * Close the stream.
 *
 * \invariant stream != NULL
 * \param[in] stream The stream to close.
 * \param[in] close_reason The error that precipitated this closure
 */
JABBERWERX_API void jw_stream_close(jw_stream *stream,
                                    jw_errcode close_reason);

/**
 * Get the stream ID associated with the stream.
 * The value returned by this function is owned by the stream.
 * This memory will be released when the stream is destroyed.
 *
 * \invariant stream != NULL
 * \param[in] stream The stream.
 * \retval const char* The associated stream ID.
 */
JABBERWERX_API const char* jw_stream_get_stream_id(jw_stream *stream);

/**
 * Get the namespace for the stream's payload.
 * The value returned by this function is owned by the stream.
 * This memory will be released when the stream is destroyed.
 *
 * \invariant stream != NULL
 * \param[in] stream The stream.
 * \retval const char* The associated namespace.
 */
JABBERWERX_API const char* jw_stream_get_namespace(jw_stream *stream);

/**
 * Get the domain associated with the stream
 * The value returned by this function is owned by the stream.
 * This memory will be released when the stream is destroyed.
 *
 * \invariant stream != NULL
 * \param[in] stream The stream.
 * \retval const char* The associated domain.
 */
JABBERWERX_API const char* jw_stream_get_domain(jw_stream *stream);

/**
 * Get the selector associated with the stream
 * The value returned by this function is owned by the stream.
 * This memory will be released when the stream is destroyed.
 *
 * \invariant stream != NULL
 * \param[in] stream The stream.
 * \retval struct event_base* The associated selector.
 */
JABBERWERX_API struct event_base* jw_stream_get_selector(jw_stream *stream);

/**
 * Gets the workq associated with the stream.
 *
 * \invariant stream != NULL
 * \param[in] stream The stream.
 * \retval jw_workq* The associated workq.
 */
JABBERWERX_API jw_workq* jw_stream_get_workq(jw_stream *stream);

/**
 * Get the collection of configuration options associated with the stream.
 * The value returned by this function is not owned by the stream. The API
 * user is expected to release the config hashtable sometime after this
 * stream is destroyed.
 *
 * \invariant stream != NULL
 * \param[in] stream The stream.
 * \retval jw_htable The associated collection of configuration options.
 */
JABBERWERX_API jw_htable *jw_stream_get_config(jw_stream *stream);

/**
 * Flag used to determine if the stream is open and ready to send and receive
 * data.
 *
 * \invariant stream != NULL
 * \param[in] stream The stream.
 * \retval bool true if the stream is open and ready.
 */
JABBERWERX_API bool jw_stream_is_open(jw_stream *stream);

/**
 * Get a stream event.  Returns the event on success and NULL if event is not
 * found.
 * The memory allocated for the event will continue to be owned by the stream.
 *
 * \invariant stream != NULL
 * \invariant name != NULL
 * \invariant *name != '\\0'
 * \param[in] stream The stream owning the event dispatcher.
 * \param[in] name The name of the event.
 * \retval jw_event The found event or NULL if it does not exist.
 */
JABBERWERX_API jw_event *jw_stream_event(jw_stream *stream,
                                        const char *name);

/**
 * Get the current stream bufferevent for this object.
 *
 * \invariant stream != NULL
 * \param[in] stream The stream owning the bufferevent.
 * \retval struct bufferevent* The currently owned bufferevent or NULL if it
 *                             does not exist.
 */
JABBERWERX_API struct bufferevent *jw_stream_get_bufferevent(jw_stream *stream);

/**
 * Set the current stream bufferevent for this object.
 *
 * This function can generate the following errors (set when returning false):
 * \li \c JW_ERR_INVALID_STATE if the stream has not yet been opened.
 * \li \c JW_ERR_INVALID_ARG if the \c struct bufferevent* argument is NULL.
 *
 * \invariant stream != NULL
 * \param[in] stream The stream getting set.
 * \param[in] bev The bufferevent to be set.
 * \param[out] err The error information (provide NULL to ignore).
 * \retval bool true if successful, false otherwise.
 */
JABBERWERX_API bool jw_stream_set_bufferevent(jw_stream          *stream,
                                              struct bufferevent *bev,
                                              jw_err             *err);

/**
 * Helper function to set a bufferevent filter on the stream.  This function
 * can be used when the newly created filter should use the \c jw_stream default
 * read and write functions.  If the filter should use customized functions
 * they must be set manually through the libevent API.
 * This function can generate the following errors (set when returning false):
 * \li \c JW_ERR_INVALID_STATE if the stream has not yet been opened.
 * \li \c JW_ERR_INVALID_ARG if the \c bufferevent_filter_cb input or output
 *                           arguements are NULL.
 * \li \c JW_ERR_NO_MEMORY if the bufferevent could not be allocated.
 *
 * \invariant stream != NULL
 * \param[in] stream The stream being filtered.
 * \param[in] input The input filter callback.
 * \param[in] output The output filter callback.
 * \param[in] options The libevent bufferevent filter create options.
 * \param[in] free_filter_ctx Callback function to clean custom \c ctx.
 * \param[in] ctx Application specific data for filter.
 * \param[out] err The error information (provide NULL to ignore).
 * \retval struct bufferevent* The new filter, or NULL if error.
 */
JABBERWERX_API struct bufferevent *
    jw_stream_add_filter(jw_stream            *stream,
                         bufferevent_filter_cb input,
                         bufferevent_filter_cb output,
                         int                   options,
                         jw_data_free_func     free_filter_ctx,
                         void                 *ctx,
                         jw_err               *err);

#ifdef __cplusplus
}
#endif

#endif  /* JABBERWERX_STREAM_H */
