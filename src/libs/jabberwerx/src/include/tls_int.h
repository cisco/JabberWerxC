/**
 * \file
 * \brief
 * Internal functions that implement required TLS functions. These are declared
 * in an internal header file to allow multiple implementations of these
 * functions in different files. Some implementations could be complex.
 *
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

#ifndef JABBERWERX_TLS_INT_H
#define JABBERWERX_TLS_INT_H

#include "jabberwerx/crypto/tls.h"
#include "jabberwerx/stream.h"

#include <event2/bufferevent.h>

#ifdef  __cplusplus
extern "C"
{
#endif

/**
 * An SSL session representing the results of a handshake attempt.
 *
 * Sessions are used during the acceptance callback to provide context to the
 * required jw_tls_proceed invocation. The session will be freed by jw_tls
 * within the proceed and should not be cached.
 *
 * Eventually sessions will be queried for certificate information.
 */
struct _jw_tls_session_int
{
    jw_tls_ctx *ctx;
    jw_stream  *stream;
    struct bufferevent *bev;
    void *data;
} _jw_tls_session;

/* The underlying ssl implementation */
struct _jw_tls_ctx_int;

/**
 * Perform any one time initializations.
 *
 * Ultimately jw_client uses this function to determine of TLS is supported.
 *
 * This function can generate the following errors (set when returning false):
 * \li \c JW_ERR_NO_MEMORY if the library could not be initialized because of
 *                         allocation errors.
 * \li \c JW_ERR_INVALID_STATE if the library could not be initialized for some
 *                             other reason, including no implementation.
 *
 * \param[in] jw_tls_ctx ctx the context
 * \param[in] jw_err The error information (provide NULL to ignore)
 * \retval bool true if the library was initialized successfully.
 */
bool _jw_tls_initialize_library(jw_err *err);

/**
 * Perform any necessary library cleanup
 */
void _jw_tls_terminate_library();

/**
 * Initialize the underlying SSL implementation.
 *
 * Implementations should allocate the jw_tls_ctx and free it in jw_tls_clean.
 *
 * This function can generate the following errors (set when returning false):
 * \li \c JW_ERR_NO_MEMORY if the library could not be initialized because of
 *                         allocation errors.
 * \li \c JW_ERR_INVALID_STATE if the library could not be initialized for some
 *                             other reason.
 *
 * \invariant ctx != NULL
 * \param[in] jw_tls_ctx ctx the context
 * \param[in] jw_err The error information (provide NULL to ignore)
 * \retval bool true if the library was initialized successfully.
 */
bool _jw_tls_ctx_initialize(jw_tls_ctx **ctx, jw_err *err);

/**
 * Allow the underlying SSL library a change to cleanup.
 *
 * \param[in] jw_tls_ctx The context
 */
void _jw_tls_ctx_clean(jw_tls_ctx *ctx);

/**
 * Create a client TLS bufferevent filter for the given bufferevent base.
 *
 * Uses the given SSL context, event base and parent buffer event to create a
 * filter that implements TLS. Per protocol, a connection attempt is immediately
 * attempted.
 *
 * If accept_cb is defined no certificate validation is attempted during the
 * SSL handshake. \see jw_tls_accept_cb.
 *
 * If set_cb is defined it will be called after creation of the filter and the
 * start of the handshake but before callback remapping to handle acceptance cb.
 *
 * This function can generate the following errors (set when returning false):
 * \li \c JW_ERR_NO_MEMORY if the library could not be initialized because of
 *                         allocation errors.
 * \li \c JW_ERR_INVALID_STATE if the bufferevent could not be created for some
 *                             other reason.
 *
 * \invariant ctx != NULL
 * \invariant stream != NULL

 * \param[in] jw_tls_ctx ctx The SSL context
 * \param[in] stream The jw_stream bound to this SSL session.
 * \param[in] accept_cb An optional ovrride of the configured accept callback.
 *            \see jw_tls_filter_stream.
 * \param[out] jw_err The error information (provide NULL to ignore)
 * \retval bool true if the bufferevent filter was created successfully.
 */
bool _jw_tls_filter_stream(jw_tls_ctx        *ctx,
                           jw_stream         *stream,
                           jw_tls_accept_cb  accept_cb,
                           jw_err           *err);

/**
 * Create a client SSL enabled socket bufferevent
 *
 * Uses the given SSL context and event base to create a socket bufferevent
 * that implements client SSL connections. The bufferevent assumes it will be
 * a client connection. The new bufferevent will be created without a bound file
 * descriptor.
 *
 * This function can generate the following errors (set when returning false):
 * \li \c JW_ERR_NO_MEMORY if the library could not be initialized because of
 *                         allocation errors.
 * \li \c JW_ERR_INVALID_STATE if the bufferevent could not be created for some
 *                             other reason.
 *
 * \invariant ctx != NULL
 * \invariant stream != NULL
 * \invariant bev_ssl != NULL
 * \param[in] jw_tls_ctx ctx The SSL context
 * \param[in] stream The jw_stream bound to this SSL session.
 * \param[in] accept_cb An optional override of the configured accept callback.
 *            \see jw_tls_filter_stream.
 * \param[out] bev_ssl The SSL enabled buffer event socket
 * \param[in] jw_err The error information (provide NULL to ignore)
 * \retval bool true if the bufferevent socket was created successfully.
 */
bool _jw_tls_socket_create(jw_tls_ctx           *ctx,
                           jw_stream            *stream,
                           jw_tls_accept_cb     accept_cb,
                           struct bufferevent **bev_ssl,
                           jw_err              *err);

/**
 * Associate a client certificate chain and private key to use for mutual
 * TLS authentication.
 *
 * This function can generate the following errors (set when returning false):
 * \li \c JW_ERR_INVALID_STATE if the functionality is not supported
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
bool _jw_tls_use_cert_chain(jw_tls_ctx *ctx,
                           const char       *cert_file,
                           const char       *private_key_file,
                           jw_err           *err);

/**
 * The SSL implementation proceed.
 *
 * \see jw_tls_proceed
 *
 * \invariant sess != NULL
 * \param[in] sess The SSL session that should be allowed to finish connection
 * \param[in] accept Flag to indicate finish with success or fail.
 */
void _jw_tls_proceed(jw_tls_session *sess, bool accept);

#ifdef  __cplusplus
}
#endif

#endif  /* JABBERWERX_TLS_INT_H */
