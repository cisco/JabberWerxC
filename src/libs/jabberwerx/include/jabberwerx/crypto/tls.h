/**
 * \file
 * \brief
 * Functions and data structures for TLS over \c jw_stream
 *
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

#ifndef JABBERWERX_CRYPTO_TLS_H
#define JABBERWERX_CRYPTO_TLS_H

#include <event2/bufferevent.h>
#include "../stream.h"


/**
 * Configuration option to specify TLS is mandatory. The value of this
 * option MUST be (bool)(uintptr_t)
 */
#define JW_TLS_CONFIG_REQUIRED "tls-required"

/**
 * Configuration option to specify a callback triggered when an invalid
 * certificate is found during TLS negotiation. The value of this
 * option MUST be a \c jw_tls_accept_cb_htable_value.
 */
#define JW_TLS_CONFIG_ACCEPT_CB "tls-accept-cb"

/**
 * Configuration option for a user defined argument passed through the
 * TLS accept callback specified by JW_TLS_CONFIG_ACCEPT_CB. If this option
 * is not supplied a NULL will be passed to the accept callback.
 */
#define JW_TLS_CONFIG_ACCEPT_CB_ARG "tls-accept-cb-arg"


/**
 * An instance of an TLS context.
 *
 * The context is used to create SSL bufferevents and is analogous to the
 * openssl SSL_CTX type.
 */
typedef struct _jw_tls_ctx_int jw_tls_ctx;

/**
 * A jw_tls_session represents the results of a handshake attempt. This pointer
 * is passed to the acceptance callback (see below) and may be queried for
 * validation error information.
 *
 * The session is passed to jw_tls_proceed to complete the handshake.
 *
 * todo provide getters for a sessions stream and bufferevent
 */
typedef struct _jw_tls_session_int jw_tls_session;


/**
 * TLS certificate acceptance callback.
 *
 * A callback fired when a certificate has failed validation during a
 * handshake attempt. The user queries the given \c jw_tls_session for certificate
 * information (todo implement) to determine if the certificate should be
 * accepted anyway. The user MUST call \c jw_tls_proceed with the given
 * TLS session to continue negotiation and finish connection.
 *
 * The accept callback may be optionally referenced in the \c jw_htable
 * configuration passed to \c jw_tls_context_create. Since function
 * and data pointers can not be cast to one another, the usual jw_htable
 * getters and setters cannot be used with the callback directly. Instead the
 * callback should be wrapped in a \c jw_tls_accept_cb_htable_value and that
 * union callback pointer reference should be added to the table using the
 * JW_TLS_CONFIG_ACCEPT_CB key.
 *
 * Users may also specify an argument to be passed through the accept callback.
 *
 * \param[in] sess The SSL handshake results (used with \c jw_tls_proceed).
 * \param[in] arg An optional user supplied argument bound to this callback.
 */
typedef void (*jw_tls_accept_cb)(jw_tls_session *sess, void *arg);

/**
 * A hashtable container for the accept callback.
 *
 * \c jw_tls_accept_cb_htable_value cb_val { .cb = myCallbackFn };
 * \c jw_htable_put(config, JW_TLS_CONFIG_ACCEPT_CB, &cb_val, NULL, NULL);
 */
typedef struct jw_tls_accept_cb_htable_value_t {
    /** the callback */
    jw_tls_accept_cb cb;
} jw_tls_accept_cb_htable_value;


#ifdef __cplusplus
extern "C"
{
#endif

/**
 * Create a new TLS/SSL context.
 *
 * An SSL context is used to create bufferevents associated with a particular
 * jw_stream (\see jw_tls_filter_stream, \see jw_tls_socket_create). jw_stream
 * may have a single, usually socket, bufferevent that can be used as a base
 * for an SSL filter. The JabberWerxC TCP socket stream is an example of this
 * type of stream.
 *
 * Alternately a jw_stream may be an abstraction without an underlying
 * bufferevent. These types of streams (BOSH for example) control their own
 * TCP connections and would use one or more SSL socket bufferevent for actual I/O.
 * Each SSL filter or socket is a seperate "SSL session". A single SSL context
 * may be used to for multiple streams and each stream may have multiple
 * sessions.
 *
 * The stream is used during construction for its options hash table.
 * and cached for later use in other jw_tls functions. For instance the
 * jw_tls_filter_create function creates a TLS filter using the stream's
 * bufferevent. Stream may be closed or reopened by the context while
 * handling connection.
 *
 * Once the stream has successfully connected (with no errors or with
 * accepted validations errors) future connects will never validate certificates
 *
 * This function can generate the following errors (set when returning false):
 * \li \c JW_ERR_NO_MEMORY if the context could not be allocated.
 * \li \c JW_ERR_NOT_IMPLEMENTED if TLS support is has not been compiled into
 * this distribution.
 * \li \c JW_ERR_INVALID_STATE if other errors occur.
 *
 * \invariant stream != NULL
 * \invariant ctx != NULL
 * \param[out] ctx The newly constructed context
 * \param[out] err The error information (provide NULL to ignore)
 * \retval bool true  on success, else false.
 */
JABBERWERX_API bool jw_tls_context_create(jw_tls_ctx **ctx,
                                          jw_err      *err);

/**
 * Destroy the given tls context by freeing resources and performing library
 * cleanup as needed.
 *
 * \param[in] ctx The context to destroy
 */
JABBERWERX_API void jw_tls_context_destroy(jw_tls_ctx *ctx);

/**
 * Create a transport layer security bufferevent filter on the given stream
 * and start SSL handshake.
 *
 * This function creates a TLS enabled filter on the given stream. Only one
 * filter can be created per jw_stream.
 *
 * A connection attempt is started during construction per protocol:
 * A TLS context MUST only be created after &lt;proceed/&gt; has been received
 * during STARTTLS negotiation (rfc6120 5.4.2.3). The context will immediately
 * attempt TLS negotiation following rfc6120 5.4.3.1 with the exceptions of:
 *  3 - the initiating entity SHOULD send a certificate to the receiving entity
 *      - cert exchange is not supported.
 *  5 - cert validation. todo make sure supported libs follow spec.
 *
 * Buffer I/O is suspended until a successful connection. It is safe
 * to write to the stream during this time and no read events will be
 * triggered. Buffer events are deferred, ensuring correct event order is
 * preserved. On success the stream will be reopened and all subsequent stream
 * reads/writes will be decrypted/encrypted.
 *
 * On certificate validation failure an optional callback will be triggered
 * (\see jw_tls_proceed). Connection (completion of handshake) will continue
 * once jw_tls_proceed has been called (\see jw_tls_accept_cb).
 * Other failures will cause the stream to be closed with an appropriate error.
 *
 * This function takes an optional override acceptance callback. The override
 * exists so that a controller can easily replace a user supplied cb without
 * having to modify the stream's configuration. This mechanism allows the
 * controller to coordinate acceptance between sockets for instance.
 *
 * This function can generate the following errors (set when returning false):
 * \li \c JW_ERR_NO_MEMORY if an allocation error occurred
 * \li \c JW_ERR_NOT_IMPLEMENTED if TLS support is has not been compiled into
 * this distribution.
 * \li \c JW_ERR_INVALID_STATE if other errors occur.
 *
 * \invariant ctx != NULL
 * \invariant stream != NULL
 * \param[in] ctx The TLS context to use
 * \param[in] stream The stream to filter
 * \param[in] accept_cb An optional override of the configured accept callback
 * \param[out] err The error information (provide NULL to ignore)
 * \retval bool true  on success, else false.
 */
JABBERWERX_API bool jw_tls_filter_stream(jw_tls_ctx      *ctx,
                                         jw_stream       *stream,
                                         jw_tls_accept_cb accept_cb,
                                         jw_err          *err);

/**
 * Create an SSL bufferevent socket.
 *
 * Using the given context create a new SSL enabled bufferevent socket. The
 * socket is not initially bound to a file descriptor and will not attempt
 * connection until later configuration.
 *
 * The resultant socket will not attempt to validate certificates during
 * subsequent connections but will log any errors found during their validation.
 * (todo implement acceptance callback for sockets)
 *
 * This function takes an optional override acceptance callback. The override
 * exists so that a controller can easily replace a user supplied cb without
 * having to modify the stream's configuration. This mechanism allows the
 * controller to coordinate acceptance between sockets for instance.

 * This function can generate the following errors (set when returning false):
 * \li \c JW_ERR_NO_MEMORY if an allocation error occurred during construction.
 * \li \c JW_ERR_NOT_IMPLEMENTED if TLS support is has not been compiled into
 * this distribution.
 *
 * \invariant ctx != NULL
 * \param[in] ctx The SSL context (and jw_stream) to use
 * \param[in] stream The jw_stream this socket is part of.
 * \param[in] accept_cb An optional override of the configured acceptance cb.
 * \param[out] bev The newly created SSL enabled bufferevent
 * \param[out] err The error information (provide NULL to ignore)
 * \retval bool true on success, else false.
 */
JABBERWERX_API bool jw_tls_socket_create(jw_tls_ctx          *ctx,
                                         jw_stream           *stream,
                                         jw_tls_accept_cb     accept_cb,
                                         struct bufferevent **bev,
                                         jw_err              *err);

/**
 * Associate a client certificate chain and private key to use for mutual
 * TLS authentication.
 *
 * This function can generate the following errors (set when returning false):
 * \li \c JW_ERR_NOT_IMPLEMENTED if TLS support is has not been compiled into
 * this distribution.
 * \li \c JW_ERR_BAD_FORMAT if the specified files could not be loaded
 *
 * \invariant ctx != NULL
 * \invariant cert_file != NULL
 * \invariant private_key_file != NULL
 * \param[in] ctx the SSL context to use
 * \param[in] cert_file the name of the file from which to load the cert chain
 * \param[in] private_key_file the name of the file from which to load the
 *            private key
 * \param[out] err The error information (provide NULL to ignore)
 * \retval bool true on success, else false.
 */
JABBERWERX_API bool jw_tls_use_cert_chain(jw_tls_ctx *ctx,
                                          const char *cert_file,
                                          const char *private_key_file,
                                          jw_err     *err);

/**
 * Allow a paused TLS connection to proceed or fail.
 *
 * If an invalid certificate is found during the SSL negotiation the
 * connection attempt is paused and an optional \c jw_tls_accept_cb callback
 * fired. Once the callback has been triggered, the user MUST call
 * \c jw_tls_proceedt to complete the connection.
 * If the callback is not provided \c jw_tls_proceed(ctx, false) is called
 * on the users behalf.
 *
 * The \c accept parameter determines whether the connection should fail or
 * continue authentication by validating the problem certificate.
 *
 * This function is a noop if the given TLS context is not paused for a
 * certificate review.
 *
 * \invariant sess != NULL
 * \param[in] sess The TLS connection context.
 * \param[in] accept  True if connection should proceed,
 *                    False if the connection should fail.
 * \retval enum bufferevent_flush_mode The destination buffer flush mode.
 */
JABBERWERX_API void jw_tls_proceed(jw_tls_session *sess, bool accept);

/**
 * do any onetime ssl library initialization.
 *
 * This function can generate the following errors (set when returning false):
 * \li \c JW_ERR_NO_MEMORY if an allocation error occurred during initialization
 * \li \c JW_ERR_NOT_IMPLEMENTED if TLS support is has not been compiled into
 * this distribution.
 *
 * \param[out] err the error if on occurred
 * \retval bool true on success, else false.
 */
JABBERWERX_API bool jw_tls_initialize(jw_err *err);

/**
 * Cleanup any TLS data structures and resources.
 *
 * While TLS initialization is performed by a jw_client (by calling
 * jw_tls_initialize at an appropriate time), jw_tls_terminate should be called
 * by the jw_client owner after the client's destruction (or at the end of
 * program execution if multiple jw_clients are used).
 *
 * \b NOTE: After this function is called, direct TLS operations (e.g. calling
 * OpenSSL directly) MUST NOT be performed.
 */
JABBERWERX_API void jw_tls_terminate();

#ifdef __cplusplus
}
#endif

#endif /* JABBERWERX_CRYPTO_TLS_H */
