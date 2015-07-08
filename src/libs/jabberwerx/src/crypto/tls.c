/**
 * \file
 *
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */
#include <jabberwerx/crypto/tls.h>
#include "../include/tls_int.h"

#include <jabberwerx/stream.h>
#include <jabberwerx/util/htable.h>
#include <jabberwerx/util/mem.h>
#include <jabberwerx/util/str.h>

#include <event2/buffer.h>

#include <stdio.h>
#include <assert.h>
#include <string.h>

/********************************************
 * Private helper funcs
 *******************************************/
jw_tls_accept_cb _get_accept_cb(jw_htable *opts)
{
    jw_tls_accept_cb ret = NULL;
    jw_tls_accept_cb_htable_value *cbv;

    if (opts)
    {
        cbv = jw_htable_get(opts, JW_TLS_CONFIG_ACCEPT_CB);
        if (cbv)
        {
            ret = cbv->cb;
        }
    }
    return ret;
}

/**
 * An auto accepting callback for sockets, passed to socket constructor to
 * ensure all certs will be accepted.
 */
static void _auto_accept_cb(jw_tls_session *sess, void *arg)
{
    UNUSED_PARAM(arg);
    jw_tls_proceed(sess, true);
}

/********************************************
 * Public functions
 *******************************************/
JABBERWERX_API bool jw_tls_initialize(jw_err *err)
{
    return _jw_tls_initialize_library(err);
}

JABBERWERX_API void jw_tls_terminate()
{
    _jw_tls_terminate_library();
}

JABBERWERX_API bool jw_tls_context_create(jw_tls_ctx **ctx,
                                          jw_err           *err)
{
    assert(ctx);

    return (jw_tls_initialize(err) &&
             _jw_tls_ctx_initialize(ctx, err));
}

JABBERWERX_API void jw_tls_context_destroy(jw_tls_ctx *ctx)
{
    _jw_tls_ctx_clean(ctx);
}

JABBERWERX_API bool jw_tls_filter_stream(jw_tls_ctx  *ctx,
                                         jw_stream   *stream,
                                         jw_tls_accept_cb  accept_cb,
                                         jw_err           *err)
{
    assert(ctx);
    assert(stream);
    jw_tls_accept_cb accept = accept_cb
                               ? accept_cb
                               : _get_accept_cb(jw_stream_get_config(stream));
    return _jw_tls_filter_stream(ctx, stream, accept, err);
}

JABBERWERX_API bool jw_tls_socket_create(jw_tls_ctx     *ctx,
                                         jw_stream      *stream,
                                         jw_tls_accept_cb     accept_cb,
                                         struct bufferevent **bev,
                                         jw_err              *err)
{
    UNUSED_PARAM(accept_cb);

    assert(ctx);
    assert(stream);
    assert(bev);

    /* NOTE currently _auto_accept_cb is never fired as socket accept callback
      is not yet implemented. */
   return _jw_tls_socket_create(ctx, stream, _auto_accept_cb, bev, err);
}

JABBERWERX_API bool jw_tls_use_cert_chain(jw_tls_ctx *ctx,
                                          const char      *cert_file,
                                          const char      *private_key_file,
                                          jw_err          *err)
{
    return _jw_tls_use_cert_chain(ctx, cert_file, private_key_file, err);
}

JABBERWERX_API void jw_tls_proceed(jw_tls_session *sess, bool accept)
{
    _jw_tls_proceed(sess, accept);
}


/****************************************************************
 * Default implementation, compile when no TLS will be supported
 ***************************************************************/
#ifdef JABBERWERX_TLS_NONE
bool _jw_tls_ctx_initialize(jw_tls_ctx **ctx, jw_err *err)
{
    UNUSED_PARAM(ctx);
    JABBERWERX_ERROR(err, JW_ERR_NOT_IMPLEMENTED);
    return false;
}

void _jw_tls_ctx_clean(jw_tls_ctx *ctx)
{
    UNUSED_PARAM(ctx);
}

bool _jw_tls_initialize_library(jw_err *err)
{
    JABBERWERX_ERROR(err, JW_ERR_NOT_IMPLEMENTED);
    return false;
}

void _jw_tls_terminate_library()
{
    //no-op
}

bool _jw_tls_filter_stream(jw_tls_ctx  *ctx,
                           jw_stream   *stream,
                           jw_tls_accept_cb  accept_cb,
                           jw_err           *err)
{
    assert(ctx);
    assert(stream);

    UNUSED_PARAM(accept_cb);
    JABBERWERX_ERROR(err, JW_ERR_NOT_IMPLEMENTED);
    return false;
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

    UNUSED_PARAM(accept_cb);
    JABBERWERX_ERROR(err, JW_ERR_NOT_IMPLEMENTED);
    return false;
}

bool _jw_tls_use_cert_chain(jw_tls_ctx *ctx,
                           const char       *cert_file,
                           const char       *private_key_file,
                           jw_err           *err)
{
    assert(ctx);
    assert(cert_file);
    assert(private_key_file);

    JABBERWERX_ERROR(err, JW_ERR_NOT_IMPLEMENTED);
    return false;
}

void _jw_tls_proceed(jw_tls_session *sess, bool accept)
{
    assert(sess);
    UNUSED_PARAM(accept);
}
#endif
