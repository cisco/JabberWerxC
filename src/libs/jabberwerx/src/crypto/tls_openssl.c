/**
 * \file
 *
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

#include <jabberwerx/stream.h>
#include <jabberwerx/util/htable.h>
#include <jabberwerx/util/mem.h>
#include <jabberwerx/util/str.h>
#include <jabberwerx/util/log.h>

#include <stdio.h>
#include <assert.h>
#include <string.h>

/* Build openssl by default */
#ifndef JABBERWERX_TLS_NONE

#include <jabberwerx/crypto/tls.h>
#include "../include/tls_int.h"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/conf.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/stack.h>
#ifndef STACK
# define STACK _STACK
#endif


#ifndef _EVENT_HAVE_OPENSSL
#define _EVENT_HAVE_OPENSSL
#endif

#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/bufferevent_ssl.h>

/****************************************************************
 * OpenSSL TLS implementation
 ***************************************************************/

/****************************************************************
 * OpenSSL private types and functions
 ***************************************************************/
/**
 * Two types of proceeds are needed to handle filters or sockets.
 *
 * The proceed callback is cached in the jw-tls_session, ultimately the openssl
 * impl of _jw_tls_proceed will use this function pointer to route.
 */
typedef void (*_openssl_proceed_cb)(jw_tls_session *sess, bool accept);

/**
 * Openssl specific jw_tls_session info. Cache accect cb so it is passed through
 * the bev event callback. Cache proceed_cb to distinguish between filter or
 * socket proceed.
 */
typedef struct _openssl_session_int
{
    jw_tls_accept_cb     accept_cb;
    void                *accept_arg;
    _openssl_proceed_cb  proceed_cb;
} *_openssl_session;

void _openssl_filter_proceed_cb(jw_tls_session *sess, bool accept)
{
    jw_err err;

    if (!accept)
    {
        jw_stream_close(sess->stream, JW_ERR_NOT_AUTHORIZED);
    }
    /* reassign existing stream bev to fixup callbacks */
    else if (!jw_stream_set_bufferevent(sess->stream,
                                       jw_stream_get_bufferevent(sess->stream),
                                       &err))
    {
        jw_log_err(JW_LOG_WARN, &err, "failed to reset bufferevent callbacks");
        jw_stream_close(sess->stream, JW_ERR_INVALID_STATE);
    }
    else
    {
        /* enable to start processing buffers, reopen in progress */
        //todo this may not be required, test
        if (0 != bufferevent_enable(jw_stream_get_bufferevent(sess->stream),
                                     EV_READ|EV_WRITE))
        {
            jw_log_err(JW_LOG_WARN, &err, "failed to re-enable bufferevent");
            jw_stream_close(sess->stream, JW_ERR_INVALID_STATE);
        }
    }
}

static void _openssl_filter_event_cb(struct bufferevent *bev,
                                     short events,
                                     void *data)
{
    SSL  *ssl;
    long  ssl_err;
    X509 *cert;

    jw_tls_session   *sess = (jw_tls_session*)data;
    _openssl_session os_sess = sess->data;

    if (events & BEV_EVENT_CONNECTED)
    {
        ssl = bufferevent_openssl_get_ssl(bev);
        ssl_err = SSL_get_verify_result(ssl);
        cert = SSL_get_peer_certificate(ssl);

        /* ssl_err is X509_V_OK if cert == NULL, cert should never be NULL
           in client */
        if ((ssl_err != X509_V_OK) || (cert == NULL))
        {
            os_sess->accept_cb(sess, os_sess->accept_arg);
        }
        else
        {
            _jw_tls_proceed(sess, true);
        }
        X509_free(cert);
    }
    else if (events & (BEV_EVENT_TIMEOUT|BEV_EVENT_ERROR|BEV_EVENT_EOF))
    {
        /* todo something. stream may already be closing */

        jw_log(JW_LOG_WARN,
               "_jw_tls_filter_conn_event_cb received an error/EOF event.");
        _jw_tls_proceed(sess, false);
    }
}

void _openssl_logger(const SSL *ssl, int where, int ret)
{
    if (where & SSL_CB_HANDSHAKE_START)
    {
        jw_log(JW_LOG_DEBUG, "OPENSSL - starting handshake");

    }
    else if (where & SSL_CB_HANDSHAKE_DONE)
    {
        jw_log(JW_LOG_DEBUG, "OPENSSL - finished handshake");
    }
    else if (where & SSL_CB_EXIT)
    {
        jw_log(JW_LOG_DEBUG, "OPENSSL %s - %s",
               ((ret == 0) ? "FAILURE" : (ret < 0) ? "ERROR" : ""),
               SSL_state_string_long(ssl));
    }
    else if (where & SSL_CB_ALERT)
    {
        jw_log(JW_LOG_DEBUG, "OPENSSL ALERT(%s) - %s(%s)",
               ((where & SSL_CB_READ) ? "READ" : "WRITE"),
               SSL_alert_type_string_long(ret),
               SSL_alert_desc_string_long(ret));
    }
    else
    {
        jw_log(JW_LOG_DEBUG, "OPENSSL - %s", SSL_state_string_long(ssl));
    }
}
/****************************************************************
 * _jw_tls implementation functions
 ***************************************************************/
bool _jw_tls_ctx_initialize(jw_tls_ctx **ctx, jw_err *err)
{
    assert(ctx);

    SSL_CTX *ssl_ctx = SSL_CTX_new(SSLv23_method());
    if (!ssl_ctx)
    {
        JABBERWERX_ERROR(err, JW_ERR_INVALID_STATE);
        return false;
    }
    SSL_CTX_set_info_callback(ssl_ctx, _openssl_logger);

    // ensure compression is disabled to save memory
#ifndef SSL_OP_NO_COMPRESSION
    // old hacky way of doing it
    {
        STACK_OF(SSL_COMP)* comp_methods = SSL_COMP_get_compression_methods();
        sk_SSL_COMP_zero(comp_methods);
    }
#else
    // proper way of doing it (>=OpenSSL-1.0)
    if (JW_LOG_DEBUG <= jw_log_get_level())
    {
        long prevOptions = SSL_CTX_get_options(ssl_ctx);
        if (0 != (SSL_OP_NO_COMPRESSION & prevOptions))
        {
            jw_log(JW_LOG_DEBUG, "SSL compression was already off");
        }
        else
        {
            jw_log(JW_LOG_DEBUG, "turning off SSL compression");
        }
    }
    if (0 == (SSL_OP_NO_COMPRESSION & SSL_CTX_set_options(
                    ssl_ctx, SSL_OP_NO_COMPRESSION)))
    {
        JABBERWERX_ERROR(err, JW_ERR_INVALID_STATE);
        SSL_CTX_free(ssl_ctx);
        return false;
    }
#endif // SSL_OP_NO_COMPRESSION

#ifndef SSL_MODE_RELEASE_BUFFERS
    // memory hog mode
    jw_log(JW_LOG_DEBUG, "loaded version of OpenSSL too old to support SSL_MODE_RELEASE_BUFFERS");
#else
    // release buffers when empty to save memory
    if (JW_LOG_DEBUG <= jw_log_get_level())
    {
        long prevMode = SSL_CTX_get_mode(ssl_ctx);
        if (0 != (SSL_MODE_RELEASE_BUFFERS & prevMode))
        {
            jw_log(JW_LOG_DEBUG, "SSL buffers already set to release mode");
        }
        else
        {
            jw_log(JW_LOG_DEBUG, "setting SSL release buffer mode");
        }
    }
    if (0 == (SSL_MODE_RELEASE_BUFFERS & SSL_CTX_set_mode(
                    ssl_ctx, SSL_MODE_RELEASE_BUFFERS)))
    {
        JABBERWERX_ERROR(err, JW_ERR_INVALID_STATE);
        SSL_CTX_free(ssl_ctx);
        return false;
    }
    // don't keep any free buffers around -- free them immediately
    ssl_ctx->freelist_max_len = 0;
#endif // SSL_MODE_RELEASE_BUFFERS

    *ctx = (jw_tls_ctx*)ssl_ctx;
    return true;
}

void _jw_tls_ctx_clean(jw_tls_ctx *ctx)
{
    if (ctx)
    {
        SSL_CTX_free((SSL_CTX *)ctx);
    }
}

bool _jw_tls_filter_stream(jw_tls_ctx      *ctx,
                           jw_stream       *stream,
                           jw_tls_accept_cb accept_cb,
                           jw_err          *err)
{
    assert(ctx);
    assert(stream);

    SSL *ssl;
    int  flags = BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS;
    struct event_base   *base;
    struct bufferevent  *bev_base, *bev_filter;
    jw_tls_session *sess;
    _openssl_session    os_sess;

    base = jw_stream_get_selector(stream);
    bev_base = jw_stream_get_bufferevent(stream);
    if (!base || !bev_base)
    {
        JABBERWERX_ERROR(err, JW_ERR_INVALID_STATE);
        return false;
    }
    ssl = SSL_new((SSL_CTX *)ctx);
    if (!ssl)
    {
        //todo lookup error, map to something more appropriate if possible
        JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
        return false;
    }

    /* If an acceptance callback is provided don't validate during connections*/
    if (accept_cb)
    {
        SSL_set_verify(ssl, SSL_VERIFY_NONE, NULL);
    }

    /* NOTE: filter attempts a connection as part of construction. */
    bev_filter = bufferevent_openssl_filter_new(base,
                                                bev_base,
                                                ssl,
                                                BUFFEREVENT_SSL_CONNECTING,
                                                flags);
    if (!bev_filter)
    {
        SSL_free(ssl);
        JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
        return false;
    }
    /* Set the new ssl bev to be the stream's bev as early as possible to
       ensure the correct bufferevent is used for I/O while connecting.
       On success, stream own bev_filter*/
    if (!jw_stream_set_bufferevent(stream, bev_filter, err))
    {
        jw_stream_close(stream, err ? err->code : JW_ERR_INVALID_STATE);
        return false;
    }

    /* setup to possibly trigger callback when bev connection event fires */
    if (accept_cb)
    {
        /* todo abstract some of this session creation/initialization */
        sess = jw_data_malloc(sizeof(_jw_tls_session));
        if (!sess)
        {
            JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
            jw_stream_close(stream, JW_ERR_NO_MEMORY);
            return false;
        }
        sess->ctx = ctx;
        sess->stream = stream;
        sess->bev = bev_filter;

        os_sess = jw_data_malloc(sizeof(struct _openssl_session_int));
        if (!os_sess)
        {
            JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
            jw_stream_close(stream, JW_ERR_NO_MEMORY);
            jw_data_free(sess);
            return false;
        }
        memset(os_sess, 0, sizeof(struct _openssl_session_int));
        sess->data = os_sess;

        os_sess->accept_cb =  accept_cb;
        os_sess->proceed_cb = _openssl_filter_proceed_cb;
        os_sess->accept_arg = jw_htable_get(jw_stream_get_config(stream),
                                            JW_TLS_CONFIG_ACCEPT_CB_ARG);

        // TODO: sess is leaked if the stream is destroyed before the cb fires
        bufferevent_setcb(bev_filter, NULL, NULL, _openssl_filter_event_cb, sess);
    }
    return true;
}

bool _jw_tls_socket_create(jw_tls_ctx     *ctx,
                           jw_stream      *stream,
                           jw_tls_accept_cb     accept_cb,
                           struct bufferevent **bev_ssl,
                           jw_err              *err)
{
    assert(ctx);
    assert(stream);
    assert(bev_ssl);

    struct event_base  *base = jw_stream_get_selector(stream);
    struct bufferevent *ret;
    int  flags = BEV_OPT_DEFER_CALLBACKS|BEV_OPT_CLOSE_ON_FREE;
    SSL *ssl   = SSL_new((SSL_CTX *)ctx);

    if (!ssl)
    {
        //todo lookup error, map to something more appropriate if possible
        JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
        return false;
    }
    if (accept_cb)
    {
        SSL_set_verify(ssl, SSL_VERIFY_NONE, NULL);
    }

    /* create an ssl socket */
    ret = bufferevent_openssl_socket_new(base,
                                         -1,
                                         ssl,
                                         BUFFEREVENT_SSL_CONNECTING,
                                         flags);
    if (!ret)
    {
        SSL_free(ssl);
        JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
        return false;
    }
    *bev_ssl = ret;
    return true;
}

bool _jw_tls_use_cert_chain(jw_tls_ctx *ctx,
                           const char       *cert_file,
                           const char       *private_key_file,
                           jw_err           *err)
{
    assert(ctx);
    assert(cert_file);
    assert(private_key_file);

    if (1 != SSL_CTX_use_certificate_chain_file((SSL_CTX*)ctx, cert_file))
    {
        jw_log(JW_LOG_WARN, "OPENSSL failed to load cert file: %s", cert_file);
        JABBERWERX_ERROR(err, JW_ERR_BAD_FORMAT);
        return false;
    }

    if (1 != SSL_CTX_use_PrivateKey_file(
                        (SSL_CTX*)ctx, private_key_file, SSL_FILETYPE_PEM))
    {
        jw_log(JW_LOG_WARN,
               "OPENSSL failed to load key file: %s", private_key_file);
        JABBERWERX_ERROR(err, JW_ERR_BAD_FORMAT);
        return false;
    }

    return true;
}

void _jw_tls_proceed(jw_tls_session *sess, bool accept)
{
    assert(sess);
    assert(sess->data);

    _openssl_session os_sess = (_openssl_session)sess->data;
    if (os_sess->proceed_cb)
    {
        os_sess->proceed_cb(sess, accept);
    }
    jw_data_free(os_sess);
    jw_data_free(sess);
}

bool _jw_tls_initialize_library(jw_err *err)
{
    UNUSED_PARAM(err);

    static bool initialized = false;

    // only initialize the underlying library once
    if (initialized)
    {
        return true;
    }
    initialized = true;

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    RAND_poll();
    return true;
}

void _jw_tls_terminate_library()
{
    // see http://www.mail-archive.com/openssl-dev@openssl.org/msg28071.html
    // for a full cleanup algorithm if we ever have further valgrind leak
    // warnings
    ERR_remove_state(0);
    ENGINE_cleanup();
    CONF_modules_unload(1);
    ERR_free_strings();
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();

    // work around compression stack not getting deallocated
    sk_pop_free((STACK *)SSL_COMP_get_compression_methods(), CRYPTO_free);
}

#endif
