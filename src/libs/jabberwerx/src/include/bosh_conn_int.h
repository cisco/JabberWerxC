/**
 * \file
 * \brief
 * Bosh connection typedefs and functions.  Private, not for use outside library
 * and unit tests.
 *
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

#ifndef JABBERWERX_BOSH_CONN_INT_H
#define JABBERWERX_BOSH_CONN_INT_H


#include <jabberwerx/dom.h>
#include <event2/buffer.h>
#include <event2/event.h>


typedef struct _bosh_conn_ctx_int *_bosh_conn_ctx;
typedef struct _bosh_conn_int     *_bosh_conn;

typedef void (*_on_response_cb)(
        struct evbuffer *buf, int http_status, int req_arg, void *arg);
typedef void (*_on_error_cb)(jw_errcode errcode, void *arg);


#ifdef __cplusplus
extern "C"
{
#endif

bool _bosh_conn_context_create(
        struct event_base   *evbase,
        int                  conn_cache_size,
        _on_response_cb      response_cb,
        _on_error_cb         error_cb,
        void                *arg, // passed back to the callbacks
        _bosh_conn_ctx      *ctx,
        jw_err              *err);
void _bosh_conn_context_destroy(_bosh_conn_ctx conn_ctx);
void _bosh_conn_context_set_label(_bosh_conn_ctx conn_ctx, const char *label);
int _bosh_conn_context_get_num_active(_bosh_conn_ctx conn_ctx);

bool _bosh_conn_create(_bosh_conn_ctx conn_ctx, _bosh_conn *conn, jw_err *err);
void _bosh_conn_destroy(_bosh_conn conn);
bool _bosh_conn_is_active(_bosh_conn conn);
bool _bosh_conn_send_request(
        _bosh_conn conn, const char *url, jw_dom_node *body,
        int timeout_ms, int req_arg, jw_err *err);

// unit test API
struct _bosh_conn_unit_test_fns
{
    bool (*context_create)(struct event_base *, int, _on_response_cb,
        _on_error_cb, void *, _bosh_conn_ctx *, jw_err *);
    void (*context_destroy)(_bosh_conn_ctx);
    void (*context_set_label)(_bosh_conn_ctx, const char *);
    int (*context_get_num_active)(_bosh_conn_ctx);

    bool (*conn_create)(_bosh_conn_ctx, _bosh_conn *, jw_err *);
    void (*conn_destroy)(_bosh_conn);
    bool (*conn_is_active)(_bosh_conn);
    bool (*conn_send_request)(
        _bosh_conn, const char *, jw_dom_node *, int, int, jw_err *);
};
// pass NULL to use default implementation
void _bosh_conn_replace_impl(struct _bosh_conn_unit_test_fns* fns);

#ifdef __cplusplus
}
#endif

#endif // JABBERWERX_BOSH_CONN_INT_H
