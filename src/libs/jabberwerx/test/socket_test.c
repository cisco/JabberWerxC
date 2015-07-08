/**
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

#include <fct.h>
#include "test_utils.h"
#include "stream_test.h"


typedef struct _test_socket_ctx_int
{
    jw_test_echosrv_core echosrv_core;
    struct bufferevent  *bevent_server;
    struct bufferevent  *bevent_client;
} *_test_socket_ctx;

static struct _test_socket_ctx_int _init_ctx = {
    .echosrv_core  = NULL,
    .bevent_server = NULL,
    .bevent_client = NULL
};


static void _on_bevent_server_read(struct bufferevent *bev, void *arg)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    _test_socket_ctx ctx = arg;
    assert(ctx);

    jw_err err;
    if (!_jw_test_echosrv_core_submit(ctx->echosrv_core,
            bufferevent_get_input(bev), bufferevent_get_output(bev), &err))
    {
        jw_log_err(JW_LOG_WARN, &err,
                   "failed to submit request to echosrv; closing");
        if (-1 == bufferevent_flush(bev, EV_READ|EV_WRITE, BEV_FINISHED))
        {
            jw_log(JW_LOG_ERROR, "failed to send EOF");
        }
        bufferevent_setcb(bev, NULL, NULL, NULL, NULL);
    }
}

static void _on_bevent_server_error(struct bufferevent *bev, short what, void *arg)
{
    UNUSED_PARAM(arg);

    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    jw_log(JW_LOG_WARN,
           "error detected on server bufferevent: %d; closing", what);
    if (-1 == bufferevent_flush(bev, EV_READ|EV_WRITE, BEV_FINISHED))
    {
        jw_log(JW_LOG_WARN, "failed to send EOF");
    }
    bufferevent_setcb(bev, NULL, NULL, NULL, NULL);
}

static void _socket_ctx_clear(_test_socket_ctx ctx)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(ctx);
    if (ctx->echosrv_core)
    {
        _jw_test_echosrv_core_destroy(ctx->echosrv_core);
        ctx->echosrv_core = NULL;
    }
    if (ctx->bevent_server)
    {
        bufferevent_free(ctx->bevent_server);
        ctx->bevent_server = NULL;
    }
    if (ctx->bevent_client)
    {
        bufferevent_free(ctx->bevent_client);
        ctx->bevent_client = NULL;
    }
}

static bool _socket_ctx_init(
        _test_socket_ctx ctx, struct event_base *evbase, jw_err *err)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(ctx);
    assert(evbase);
    assert(!ctx->echosrv_core);
    assert(!ctx->bevent_client);
    assert(!ctx->bevent_server);

    struct bufferevent *bevent_pair[2];
    if (0 != bufferevent_pair_new(evbase, 0, bevent_pair))
    {
        JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
        return false;
    }
    ctx->bevent_server = bevent_pair[0];
    ctx->bevent_client = bevent_pair[1];

    bufferevent_enable(ctx->bevent_client, EV_READ|EV_WRITE);
    bufferevent_enable(ctx->bevent_server, EV_READ|EV_WRITE);
    bufferevent_setcb(ctx->bevent_server, _on_bevent_server_read,
                      NULL, _on_bevent_server_error, ctx);

    if (!_jw_test_echosrv_core_create(&ctx->echosrv_core, err))
    {
        _socket_ctx_clear(ctx);
        return false;
    }

    return true;
}

static bool _before_bind_bevent(
        jw_stream *stream, jw_htable *config, void *arg, bool *failed)
{
    UNUSED_PARAM(stream);
    UNUSED_PARAM(failed);

    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    _test_socket_ctx ctx = arg;
    assert(ctx);
    assert(config);

    struct event_base *evbase =
        jw_htable_get(config, JW_STREAM_CONFIG_SELECTOR);

    return _socket_ctx_init(ctx, evbase, NULL)
        && jw_htable_put(config, JW_STREAM_CONFIG_BUFFEREVENT,
                         ctx->bevent_client, NULL, NULL)
        && jw_htable_put(config, JW_STREAM_CONFIG_LOG_LABEL,
                         "socktest", NULL, NULL);
}

static void _before_cleanup_bevent(void *arg)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    _test_socket_ctx ctx = arg;
    assert(ctx);
    _socket_ctx_clear(ctx);
}

static bool _before_bind_network(
                jw_stream *stream, jw_htable *config, void *arg, bool *failed)
{
    UNUSED_PARAM(stream);
    UNUSED_PARAM(failed);

    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    jw_test_echosrv *echosrv = arg;
    assert(echosrv);
    assert(config);

    return _jw_test_echosrv_create(jw_stream_get_workq(stream), echosrv, NULL)
        && _test_config_set_echosrv_port(config, *echosrv);
}

static void _before_cleanup_network(void *arg)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    jw_test_echosrv *echosrv = arg;
    assert(echosrv);
    if (*echosrv)
    {
        _jw_test_echosrv_destroy(*echosrv);
        *echosrv = NULL;
    }
}


static jw_loglevel _initlevel;
FCTMF_FIXTURE_SUITE_BGN(socket_test)
{
    FCT_SETUP_BGN()
    {
        _initlevel = jw_log_get_level();
        _test_init_counting_memory_funcs();
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
    } FCT_TEARDOWN_END()

    FCT_TEST_BGN(socket_test_no_config)
    {
        //jw_log_set_level(JW_LOG_TRACE);
        struct _test_stream_hooks hooks;
        _test_stream_hooks_init(jw_stream_socket_create, &hooks);
        fct_chk(_test_stream_no_config(&hooks, NULL));
    } FCT_TEST_END()

    FCT_TEST_BGN(socket_test_destroy_from_close)
    {
        //jw_log_set_level(JW_LOG_TRACE);
        struct _test_socket_ctx_int ctx = _init_ctx;
        struct _test_stream_hooks hooks;
        _test_stream_hooks_init(jw_stream_socket_create, &hooks);
        hooks.before_bind_cb        = _before_bind_bevent;
        hooks.before_bind_cb_arg    = &ctx;
        hooks.before_cleanup_cb     = _before_cleanup_bevent;
        hooks.before_cleanup_cb_arg = &ctx;
        fct_chk(_test_stream_destroy_from_close(&hooks, NULL));
    } FCT_TEST_END()

    FCT_TEST_BGN(socket_test_happy)
    {
        //jw_log_set_level(JW_LOG_TRACE);
        struct _test_socket_ctx_int ctx = _init_ctx;
        struct _test_stream_hooks hooks;
        _test_stream_hooks_init(jw_stream_socket_create, &hooks);
        hooks.before_bind_cb        = _before_bind_bevent;
        hooks.before_bind_cb_arg    = &ctx;
        hooks.before_cleanup_cb     = _before_cleanup_bevent;
        hooks.before_cleanup_cb_arg = &ctx;
        fct_chk(_test_stream_basic(&hooks, NULL));
    } FCT_TEST_END()

// TODO: currently fails due to DE2808
//    FCT_TEST_BGN(socket_test_error_elem)
//    {
//        jw_log_set_level(JW_LOG_DEBUG);
//        struct _test_socket_ctx_int ctx = _init_ctx;
//        struct _test_stream_hooks hooks;
//        _test_stream_hooks_init(jw_stream_socket_create, &hooks);
//        hooks.before_bind_cb        = _before_bind_bevent;
//        hooks.before_bind_cb_arg    = &ctx;
//        hooks.before_cleanup_cb     = _before_cleanup_bevent;
//        hooks.before_cleanup_cb_arg = &ctx;
//        fct_chk(_test_stream_error_elem(&hooks, NULL));
//    } FCT_TEST_END()

    FCT_TEST_BGN(socket_test_oom)
    {
        //jw_log_set_level(JW_LOG_TRACE);

        jw_err err;

        // override expat allocators until the leak in expat is sussed out
        // (see parser.c:50)
        _test_remove_expat_malloc_monitoring();

        struct _test_socket_ctx_int ctx = _init_ctx;
        struct _test_stream_hooks hooks;
        _test_stream_hooks_init(jw_stream_socket_create, &hooks);
        hooks.before_bind_cb        = _before_bind_bevent;
        hooks.before_bind_cb_arg    = &ctx;
        hooks.before_cleanup_cb     = _before_cleanup_bevent;
        hooks.before_cleanup_cb_arg = &ctx;

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

    FCT_TEST_BGN(socket_test_network)
    {
        //jw_log_set_level(JW_LOG_TRACE);

        jw_err err;

        // override expat allocators until the leak in expat is sussed out
        // (see parser.c:50)
        _test_remove_expat_malloc_monitoring();

        jw_test_echosrv echosrv = NULL;
        struct _test_stream_hooks hooks;
        _test_stream_hooks_init(jw_stream_socket_create, &hooks);
        hooks.before_bind_cb        = _before_bind_network;
        hooks.before_bind_cb_arg    = &echosrv;
        hooks.before_cleanup_cb     = _before_cleanup_network;
        hooks.before_cleanup_cb_arg = &echosrv;

        OOM_RECORD_ALLOCS(_test_stream_basic(&hooks, &err));
        OOM_TEST_INIT();
        if (_test_get_timed_out()) { break; }
        OOM_TEST_NO_CHECK(&err, _test_stream_basic(&hooks, &err));
        fct_req(!_test_get_timed_out());

        OOM_TEST_INIT();
        if (_test_get_timed_out()) { break; }
        OOM_TEST_NO_CHECK(NULL, _test_stream_basic(&hooks, NULL));
        fct_req(!_test_get_timed_out());

        _test_restore_expat_malloc_monitoring();
    } FCT_TEST_END()
} FCTMF_FIXTURE_SUITE_END()
