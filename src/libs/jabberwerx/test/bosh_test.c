/**
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

#include <fct.h>
#include <jabberwerx/stream.h>

#ifndef JABBERWERX_NO_BOSH

#include <jabberwerx/util/serializer.h>
#include "../src/include/bosh_conn_int.h"
#include "test_utils.h"
#include "stream_test.h"


typedef struct _test_bosh_conn_ctx_int
{
    jw_test_echosrv_core echosrv_core;
    struct event_base   *evbase;

    const char *log_label;
    int         num_active;
    void       *cb_arg;

    _on_response_cb response_cb;
    _on_error_cb    error_cb;
} *_test_bosh_conn_ctx;

typedef struct _test_bosh_conn_int
{
    _test_bosh_conn_ctx ctx;
    const char         *url;
    struct evbuffer    *response;
    struct event       *resp_event;
    int                 req_arg;
    bool                active;
} *_test_bosh_conn;


static bool _test_bosh_conn_context_create(
        struct event_base   *evbase,
        int                  conn_cache_size,
        _on_response_cb      response_cb,
        _on_error_cb         error_cb,
        void                *arg,
        _bosh_conn_ctx      *retctx,
        jw_err              *err)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    UNUSED_PARAM(conn_cache_size);
    assert(retctx);

    jw_test_echosrv_core echosrv_core;
    if (!_jw_test_echosrv_core_create(&echosrv_core, err))
    {
        return false;
    }

    _test_bosh_conn_ctx ctx =
            jw_data_calloc(1, sizeof(struct _test_bosh_conn_ctx_int));
    if (!ctx)
    {
        JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
        _jw_test_echosrv_core_destroy(echosrv_core);
        return false;
    }

    ctx->echosrv_core = echosrv_core;
    ctx->evbase       = evbase;
    ctx->response_cb  = response_cb;
    ctx->error_cb     = error_cb;
    ctx->cb_arg       = arg;

    *retctx = (_bosh_conn_ctx)ctx;
    return true;
}

static void _test_bosh_conn_context_destroy(_bosh_conn_ctx conn_ctx)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(conn_ctx);
    _test_bosh_conn_ctx test_ctx = (_test_bosh_conn_ctx)conn_ctx;
    _jw_test_echosrv_core_destroy(test_ctx->echosrv_core);
    jw_data_free(test_ctx);
}

static void _test_bosh_conn_context_set_label(
        _bosh_conn_ctx conn_ctx, const char *label)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(conn_ctx);
    _test_bosh_conn_ctx test_ctx = (_test_bosh_conn_ctx)conn_ctx;
    test_ctx->log_label = label;
}

static int _test_bosh_conn_context_get_num_active(_bosh_conn_ctx conn_ctx)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(conn_ctx);
    _test_bosh_conn_ctx test_ctx = (_test_bosh_conn_ctx)conn_ctx;
    return test_ctx->num_active;
}
static bool _test_bosh_conn_is_active(_bosh_conn conn)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(conn);
    _test_bosh_conn test_conn = (_test_bosh_conn)conn;
    return test_conn->active;
}

static void _test_bosh_send_response_cb(evutil_socket_t fd, short f, void *arg)
{
    UNUSED_PARAM(fd);
    UNUSED_PARAM(f);

    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    _test_bosh_conn test_conn = arg;
    assert(test_conn);
    _test_bosh_conn_ctx test_ctx = test_conn->ctx;
    assert(test_ctx);
    assert(test_ctx->response_cb);
    assert(test_conn->response);

    struct evbuffer *response = test_conn->response;

    test_conn->active = false;
    --test_ctx->num_active;
    test_conn->response = NULL;

    test_ctx->response_cb(response, 200, test_conn->req_arg, test_ctx->cb_arg);
    evbuffer_free(response);
}


static bool _test_bosh_conn_create(
        _bosh_conn_ctx conn_ctx, _bosh_conn *retconn, jw_err *err)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(conn_ctx);
    assert(retconn);

    _test_bosh_conn test_conn =
            jw_data_calloc(1, sizeof(struct _test_bosh_conn_int));
    if (!test_conn)
    {
        JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
        return false;
    }

    test_conn->ctx = (_test_bosh_conn_ctx)conn_ctx;
    test_conn->resp_event =
          evtimer_new(test_conn->ctx->evbase,
                      _test_bosh_send_response_cb, test_conn);

    if (!test_conn->resp_event)
    {
        JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
        jw_data_free(test_conn);
        return false;
    }

    *retconn = (_bosh_conn)test_conn;
    return true;
}

static void _test_bosh_conn_destroy(_bosh_conn conn)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(conn);
    _test_bosh_conn test_conn = (_test_bosh_conn)conn;

    if (test_conn->response)
    {
        evbuffer_free(test_conn->response);
    }

    if (test_conn->resp_event)
    {
        event_free(test_conn->resp_event);
    }

    jw_data_free(test_conn);
}

bool (*_on_send_hook)(_test_bosh_conn_ctx test_ctx,
                      jw_dom_node *body, jw_err *err) = NULL;
void *_on_send_hook_data = NULL;

static bool _test_bosh_conn_send_request(
        _bosh_conn conn, const char *url, jw_dom_node *body,
        int timeout_ms, int req_arg, jw_err *err)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    UNUSED_PARAM(timeout_ms);
    UNUSED_PARAM(err);

    assert(conn);
    _test_bosh_conn test_conn = (_test_bosh_conn)conn;
    assert(!test_conn->response);
    assert(!test_conn->active);
    _test_bosh_conn_ctx test_ctx = test_conn->ctx;
    assert(test_ctx);

    if (_on_send_hook)
    {
        if (!_on_send_hook(test_ctx, body, err))
        {
            return false;
        }
    }

    struct evbuffer *req  = evbuffer_new();
    struct evbuffer *resp = evbuffer_new();
    if (!req || !resp)
    {
        JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
        if (req)  { evbuffer_free(req);  }
        if (resp) { evbuffer_free(resp); }
        return false;
    }

    if (!jw_serialize_xml_buffer(body, req, NULL, err)
     || !_jw_test_echosrv_core_submit(test_ctx->echosrv_core, req, resp, err))
    {
        evbuffer_free(req);
        evbuffer_free(resp);
        return false;
    }

    test_conn->response = resp;
    test_conn->url      = url;
    test_conn->req_arg  = req_arg;
    test_conn->active   = true;
    ++test_ctx->num_active;

    event_active(test_conn->resp_event, EV_TIMEOUT, 0);
    evbuffer_free(req);
    
    return true;
}

bool _unsend_see_other_uri(
        _test_bosh_conn_ctx test_ctx, jw_dom_node *body, jw_err *err)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(body);

    _on_send_hook      = NULL;
    _on_send_hook_data = NULL;

    _jw_test_echosrv_core_remove_command(body);

    // new stream; reset echosrv_core state
    jw_test_echosrv_core echosrv_core;
    if (!_jw_test_echosrv_core_create(&echosrv_core, err))
    {
        return false;
    }

    _jw_test_echosrv_core_destroy(test_ctx->echosrv_core);
    test_ctx->echosrv_core = echosrv_core;
    return true;
}

bool _send_see_other_uri(
        _test_bosh_conn_ctx test_ctx, jw_dom_node *body, jw_err *err)
{
    UNUSED_PARAM(test_ctx);

    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(body);

    // <body condition='see-other-uri' type='terminate'
    //       xmlns='http://jabber.org/protocol/httpbind'>
    //   <uri>target_url</uri>
    // </body>
    jw_dom_ctx  *ctx = jw_dom_get_context(body);
    jw_dom_node *retbody, *uri, *uritext;
    const char  *uristr = _on_send_hook_data;

    _on_send_hook      = _unsend_see_other_uri;
    _on_send_hook_data = NULL;

    return jw_dom_element_create(ctx,
                                 "{http://jabber.org/protocol/httpbind}body",
                                 &retbody, err)
        && jw_dom_set_attribute(retbody, "{}condition", "see-other-uri", err)
        && jw_dom_set_attribute(retbody, "{}type",      "terminate",     err)
        && jw_dom_element_create(ctx, "{}uri", &uri, err)
        && jw_dom_text_create(ctx, uristr, &uritext, err)
        && jw_dom_add_child(uri, uritext, err)
        && jw_dom_add_child(retbody, uri, err)
        && _jw_test_echosrv_core_add_command(
            body, JW_ECHOSRV_CMD_SEND, retbody, err);
}


static struct _bosh_conn_unit_test_fns _test_fns = {
    .context_create         = _test_bosh_conn_context_create,
    .context_destroy        = _test_bosh_conn_context_destroy,
    .context_set_label      = _test_bosh_conn_context_set_label,
    .context_get_num_active = _test_bosh_conn_context_get_num_active,
    .conn_create            = _test_bosh_conn_create,
    .conn_destroy           = _test_bosh_conn_destroy,
    .conn_is_active         = _test_bosh_conn_is_active,
    .conn_send_request      = _test_bosh_conn_send_request
};

static jw_loglevel _initlevel;
FCTMF_FIXTURE_SUITE_BGN(bosh_test)
{
    FCT_SETUP_BGN()
    {
        _initlevel = jw_log_get_level();
        _test_init_counting_memory_funcs();
        _bosh_conn_replace_impl(&_test_fns);
        _on_send_hook = NULL;
    } FCT_SETUP_END()

    FCT_TEARDOWN_BGN()
    {
        fct_chk_eq_int(_test_get_free_count(), _test_get_malloc_count());
        if (_test_get_free_count() != _test_get_malloc_count())
        {
            jw_log(JW_LOG_ERROR,
                   "mem leak detected in %s: %u allocations, %u frees",
                   fctkern_ptr__->ns.curr_test_name,
                   _test_get_malloc_count(), _test_get_free_count());
        }
        _test_uninit_counting_memory_funcs();
        jw_log_set_level(_initlevel);
        _bosh_conn_replace_impl(NULL);
    } FCT_TEARDOWN_END()

    FCT_TEST_BGN(bosh_test_no_config)
    {
        //jw_log_set_level(JW_LOG_TRACE);
        struct _test_stream_hooks hooks;
        _test_stream_hooks_init(jw_stream_bosh_create, &hooks);
        fct_chk(_test_stream_no_config(&hooks, NULL));
    } FCT_TEST_END()

    FCT_TEST_BGN(bosh_test_destroy_from_close)
    {
        //jw_log_set_level(JW_LOG_TRACE);
        struct _test_stream_hooks hooks;
        _test_stream_hooks_init(jw_stream_bosh_create, &hooks);
        fct_chk(_test_stream_destroy_from_close(&hooks, NULL));
    } FCT_TEST_END()

    FCT_TEST_BGN(bosh_test_happy)
    {
        //jw_log_set_level(JW_LOG_TRACE);
        struct _test_stream_hooks hooks;
        _test_stream_hooks_init(jw_stream_bosh_create, &hooks);
        fct_chk(_test_stream_basic(&hooks, NULL));
    } FCT_TEST_END()

// TODO: currently fails due to DE2808
//    FCT_TEST_BGN(bosh_test_error_elem)
//    {
//        //jw_log_set_level(JW_LOG_TRACE);
//        struct _test_stream_hooks hooks;
//        _test_stream_hooks_init(jw_stream_bosh_create, &hooks);
//        fct_chk(_test_stream_error_elem(&hooks, NULL));
//    } FCT_TEST_END()

    FCT_TEST_BGN(bosh_test_see_other_uri)
    {
        //jw_log_set_level(JW_LOG_TRACE);
        struct _test_stream_hooks hooks;
        _test_stream_hooks_init(jw_stream_bosh_create, &hooks);

        // valid redirect
        _on_send_hook      = _send_see_other_uri;
        _on_send_hook_data = "http://127.0.0.1/xmppcm";
        fct_chk(_test_stream_basic(&hooks, NULL));

        // invalid redirect
        _on_send_hook      = _send_see_other_uri;
        _on_send_hook_data = "http://differenthost.com/bosh";
        fct_chk(!_test_stream_basic(&hooks, NULL));

        // invalid redirect
        _on_send_hook      = _send_see_other_uri;
        _on_send_hook_data = "https://127.0.0.1/xmppcm";
        fct_chk(!_test_stream_basic(&hooks, NULL));
    } FCT_TEST_END()

    FCT_TEST_BGN(bosh_test_oom)
    {
        //jw_log_set_level(JW_LOG_TRACE);

        jw_err err;

        // override expat allocators until the leak in expat is sussed out
        // (see parser.c:50)
        _test_remove_expat_malloc_monitoring();

        struct _test_stream_hooks hooks;
        _test_stream_hooks_init(jw_stream_bosh_create, &hooks);

        OOM_RECORD_ALLOCS(_test_stream_keepalive(&hooks, &err));
        OOM_TEST_INIT();
        if (_test_get_timed_out()) { break; }
        OOM_TEST_NO_CHECK(&err, _test_stream_keepalive(&hooks, &err));
        fct_req(!_test_get_timed_out());
        
        OOM_TEST_INIT();
        if (_test_get_timed_out()) { break; }
        OOM_TEST_NO_CHECK(NULL, _test_stream_keepalive(&hooks, NULL));
        fct_req(!_test_get_timed_out());

        _test_restore_expat_malloc_monitoring();
    } FCT_TEST_END()
} FCTMF_FIXTURE_SUITE_END()

#else

FCTMF_SUITE_BGN(bosh_test)
{
    FCT_TEST_BGN(bosh_test_not_implemented)
    {
        //jw_log_set_level(JW_LOG_TRACE);

        jw_stream *stream;
        jw_err          err;

        fct_chk(!jw_stream_bosh_create(NULL, &stream, &err));
        fct_chk_eq_int(JW_ERR_NOT_IMPLEMENTED, err.code);
    } FCT_TEST_END()
} FCTMF_SUITE_END()

#endif
