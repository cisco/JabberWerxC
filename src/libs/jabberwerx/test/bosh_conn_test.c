/**
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

#define _GNU_SOURCE // for asprintf on linux
#include <stdio.h>

#ifndef JABBERWERX_NO_BOSH

#include <fct.h>
#include "test_utils.h"
#include "httpsrv.h"
#include "../src/include/bosh_conn_int.h"
#include "../src/include/stream_int.h"

struct _cb_record
{
    int latest_call_idx;
    int num_calls;
};

struct _cb_data
{
    struct event_base *evbase;
    int                next_call_idx;

    struct _cb_record response_record;
    struct _cb_record error_record;

    const char *expected_response;
    bool        expected_response_matched;
    int         expected_status;
    bool        expected_status_matched;
    jw_errcode  errcode;
};

static void _init_cb_data(struct _cb_data *cb_data, struct event_base *evbase)
{
    memset(cb_data, 0, sizeof(struct _cb_data));
    cb_data->evbase = evbase;
}

static void _update_cb_data(struct _cb_data *cb_data, struct _cb_record *record)
{
    record->latest_call_idx = cb_data->next_call_idx++;
    ++record->num_calls;
}

static void _on_response(
        struct evbuffer *buf, int http_status, int req_arg, void *arg)
{
    UNUSED_PARAM(req_arg);
    
    _log_evbuffer(JW_LOG_DEBUG, buf, "_on_response called with");

    struct _cb_data *cb_data = arg;
    _update_cb_data(cb_data, &cb_data->response_record);
    
    cb_data->expected_status_matched = http_status == cb_data->expected_status;

    if (cb_data->expected_response)
    {
        jw_log(JW_LOG_DEBUG, "expecting: '%s'", cb_data->expected_response);
        size_t      expected_len = strlen(cb_data->expected_response);
        const char *expected     = cb_data->expected_response;
        cb_data->expected_response_matched =
                expected_len == evbuffer_get_length(buf)
             && 0 == evbuffer_search(buf, expected, expected_len, NULL).pos;
    }

    if (0 == event_base_got_exit(cb_data->evbase))
    {
        jw_log(JW_LOG_DEBUG, "requesting event loop termination");
        event_base_loopexit(cb_data->evbase, NULL);
    }
}

static void _on_error(jw_errcode errcode, void *arg)
{
    jw_log(JW_LOG_DEBUG, "_on_error called");

    struct _cb_data *cb_data = arg;
    _update_cb_data(cb_data, &cb_data->error_record);
    cb_data->errcode = errcode;

    if (0 == event_base_got_exit(cb_data->evbase))
    {
        jw_log(JW_LOG_DEBUG, "requesting event loop termination");
        event_base_loopexit(cb_data->evbase, NULL);
    }
}

static void _evloop(struct event_base *evbase)
{
    jw_log(JW_LOG_DEBUG, "starting event loop");
    event_base_dispatch(evbase);
    jw_log(JW_LOG_DEBUG, "returning from event loop");
}

static bool _send_and_loop(
        _bosh_conn conn, const char *url, jw_dom_node *body,
        struct event_base *evbase, jw_err *err)
{
    if (!_bosh_conn_send_request(conn, url, body, 0, -1, err))
    {
        return false;
    }

    if (_bosh_conn_is_active(conn))
    {
        _evloop(evbase);
    }

    return true;
}


static jw_loglevel _initlevel;
FCTMF_FIXTURE_SUITE_BGN(bosh_conn_test)
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
                   "mem leak detected in %s: mallocCnt=%d; freeCnt=%d",
                   fctkern_ptr__->ns.curr_test_name,
                   _test_get_malloc_count(), _test_get_free_count());
        }
        _test_uninit_counting_memory_funcs();
        jw_log_set_level(_initlevel);
    } FCT_TEARDOWN_END()

    FCT_TEST_BGN(bosh_conn_allocate_destroy)
    {
        //jw_log_set_level(JW_LOG_TRACE);
        
        struct event_base *evbase;
        fct_req(_test_init(&evbase, NULL, NULL, NULL, NULL));

        struct _cb_data cb_data;
        _init_cb_data(&cb_data, evbase);

        // test context create-destroy
        _bosh_conn_ctx conn_ctx;
        fct_req(_bosh_conn_context_create(evbase, 2,
                    _on_response, _on_error, &cb_data, &conn_ctx, NULL));
        fct_chk_eq_int(0, _bosh_conn_context_get_num_active(conn_ctx));
        fct_chk_eq_int(0, cb_data.next_call_idx);
        _bosh_conn_context_destroy(conn_ctx);

        jw_err err;
        OOM_RECORD_ALLOCS(_bosh_conn_context_create(evbase, 2,
                    _on_response, _on_error, &cb_data, &conn_ctx, &err));
        OOM_TEST_INIT();
        OOM_TEST(&err, _bosh_conn_context_create(evbase, 2,
                    _on_response, _on_error, &cb_data, &conn_ctx, &err));
        OOM_TEST_INIT();
        OOM_TEST(NULL, _bosh_conn_context_create(evbase, 2,
                    _on_response, _on_error, &cb_data, &conn_ctx, NULL));

        // test conn create-destroy
        _bosh_conn conn;
        fct_req(_bosh_conn_create(conn_ctx, &conn, NULL));
        fct_chk(!_bosh_conn_is_active(conn));
        fct_chk_eq_int(0, _bosh_conn_context_get_num_active(conn_ctx));
        _bosh_conn_destroy(conn);

        OOM_RECORD_ALLOCS(_bosh_conn_create(conn_ctx, &conn, &err));
        _bosh_conn_destroy(conn);
        OOM_TEST_INIT();
        OOM_TEST(&err, _bosh_conn_create(conn_ctx, &conn, &err));
        OOM_TEST_INIT();
        OOM_TEST(NULL, _bosh_conn_create(conn_ctx, &conn, NULL));

        fct_chk_eq_int(0, cb_data.next_call_idx);
        _bosh_conn_context_destroy(conn_ctx);
        
        _test_cleanup(evbase, NULL, NULL, NULL, NULL);
    } FCT_TEST_END()

    FCT_TEST_BGN(bosh_conn_send_request)
    {
        //jw_log_set_level(JW_LOG_TRACE);

        struct event_base *evbase;
        struct event      *failsafeEvent;
        jw_httpsrv         httpsrv;
        struct _cb_data    cb_data;
        _bosh_conn_ctx     conn_ctx;
        _bosh_conn         conn;

        fct_req(_test_init(&evbase, &failsafeEvent, NULL, NULL, NULL));
        _init_cb_data(&cb_data, evbase);
        fct_req(jw_httpsrv_create(evbase, &httpsrv, NULL));
        fct_req(_bosh_conn_context_create(evbase, 2,
                    _on_response, _on_error, &cb_data, &conn_ctx, NULL));
        _bosh_conn_context_set_label(conn_ctx, "bosh_conn_send_request");
        fct_req(_bosh_conn_create(conn_ctx, &conn, NULL));

        jw_dom_ctx *dom_ctx;
        jw_dom_node *body;
        fct_req(jw_dom_context_create(&dom_ctx, NULL));
        fct_req(jw_dom_element_create(dom_ctx, "{}testnode", &body, NULL));

        char *url;
        fct_req(asprintf(&url, "http://127.0.0.1:%u",
                         jw_httpsrv_get_port(httpsrv)));

        fct_chk(!_bosh_conn_is_active(conn));
        fct_chk(_bosh_conn_send_request(conn, url, body, 0, -1, NULL));
        fct_chk(_bosh_conn_is_active(conn));
        _evloop(evbase);
        fct_req(!_test_get_timed_out());
        fct_chk(!_bosh_conn_is_active(conn));
        fct_chk_eq_int(0, cb_data.error_record.num_calls);
        fct_chk_eq_int(1, cb_data.response_record.num_calls);
        fct_req(!_test_get_timed_out());

        const char *response = "dummy response";
        _init_cb_data(&cb_data, evbase);
        cb_data.expected_response = response;
        fct_req(jw_httpsrv_set_next_response(httpsrv, 200, response));
        fct_chk(_bosh_conn_send_request(conn, url, body, 0, -1, NULL));
        fct_chk(_bosh_conn_is_active(conn));
        _evloop(evbase);
        fct_req(!_test_get_timed_out());
        fct_chk(!_bosh_conn_is_active(conn));
        fct_chk(cb_data.expected_response_matched);
        fct_chk_eq_int(0, cb_data.error_record.num_calls);
        fct_chk_eq_int(1, cb_data.response_record.num_calls);

        jw_dom_context_destroy(dom_ctx);
        _bosh_conn_destroy(conn);
        _bosh_conn_context_destroy(conn_ctx);
        free(url);
        jw_httpsrv_destroy(httpsrv);
        _test_cleanup(evbase, failsafeEvent, NULL, NULL, NULL);
    } FCT_TEST_END()

    FCT_TEST_BGN(bosh_conn_oom)
    {
        //jw_log_set_level(JW_LOG_TRACE);

        struct event_base *evbase;
        struct event      *failsafeEvent;
        jw_httpsrv         httpsrv;
        struct _cb_data    cb_data;
        _bosh_conn_ctx     conn_ctx;
        _bosh_conn         conn;
        jw_err             err;

        fct_req(_test_init(&evbase, &failsafeEvent, NULL, NULL, NULL));
        _init_cb_data(&cb_data, evbase);
        fct_req(jw_httpsrv_create(evbase, &httpsrv, NULL));
        fct_req(_bosh_conn_context_create(evbase, 2,
                    _on_response, _on_error, &cb_data, &conn_ctx, NULL));
        _bosh_conn_context_set_label(conn_ctx, "bosh_conn_oom");
        fct_req(_bosh_conn_create(conn_ctx, &conn, NULL));

        jw_dom_ctx *dom_ctx;
        jw_dom_node *body;
        fct_req(jw_dom_context_create(&dom_ctx, NULL));
        fct_req(jw_dom_element_create(dom_ctx, "{}testnode", &body, NULL));

        char *url;
        fct_req(asprintf(&url, "http://127.0.0.1:%u",
                         jw_httpsrv_get_port(httpsrv)));

        const char *response = "dummy response";
        fct_req(jw_httpsrv_set_next_response(httpsrv, 200, response));
        OOM_RECORD_ALLOCS(_send_and_loop(conn, url, body, evbase, NULL));
        OOM_TEST_INIT();
        fct_req(!_test_get_timed_out());
        _init_cb_data(&cb_data, evbase);
        _bosh_conn_destroy(conn);
        fct_req(_bosh_conn_create(conn_ctx, &conn, NULL));
        fct_req(jw_httpsrv_set_next_response(httpsrv, 200, response));
        OOM_TEST_NO_CHECK(&err, _send_and_loop(conn, url, body, evbase, &err));
        OOM_TEST_INIT();
        fct_req(!_test_get_timed_out());
        _init_cb_data(&cb_data, evbase);
        _bosh_conn_destroy(conn);
        fct_req(_bosh_conn_create(conn_ctx, &conn, NULL));
        fct_req(jw_httpsrv_set_next_response(httpsrv, 200, response));
        OOM_TEST_NO_CHECK(NULL, _send_and_loop(conn, url, body, evbase, NULL));
        fct_req(!_test_get_timed_out());

        jw_dom_context_destroy(dom_ctx);
        _bosh_conn_destroy(conn);
        _bosh_conn_context_destroy(conn_ctx);
        free(url);
        jw_httpsrv_destroy(httpsrv);
        _test_cleanup(evbase, failsafeEvent, NULL, NULL, NULL);
    } FCT_TEST_END()

    FCT_TEST_BGN(bosh_conn_server_error)
    {
        //jw_log_set_level(JW_LOG_TRACE);

        struct event_base *evbase;
        struct event      *failsafeEvent;
        jw_httpsrv         httpsrv;
        struct _cb_data    cb_data;
        _bosh_conn_ctx     conn_ctx;
        _bosh_conn         conn;

        fct_req(_test_init(&evbase, &failsafeEvent, NULL, NULL, NULL));
        _init_cb_data(&cb_data, evbase);
        fct_req(jw_httpsrv_create(evbase, &httpsrv, NULL));
        fct_req(_bosh_conn_context_create(evbase, 2,
                    _on_response, _on_error, &cb_data, &conn_ctx, NULL));
        _bosh_conn_context_set_label(conn_ctx, "bosh_conn_server_error");
        fct_req(_bosh_conn_create(conn_ctx, &conn, NULL));

        jw_dom_ctx *dom_ctx;
        jw_dom_node *body;
        fct_req(jw_dom_context_create(&dom_ctx, NULL));
        fct_req(jw_dom_element_create(dom_ctx, "{}testnode", &body, NULL));

        char *url;
        fct_req(asprintf(&url, "http://127.0.0.1:%u",
                         jw_httpsrv_get_port(httpsrv)));

        // test server error
        cb_data.expected_status = 500;
        fct_req(jw_httpsrv_set_next_response(httpsrv, 500, NULL));
        fct_chk(_send_and_loop(conn, url, body, evbase, NULL));
        fct_req(0 < cb_data.response_record.num_calls);
        fct_chk(cb_data.expected_status_matched);
        fct_req(!_test_get_timed_out());

        // test connection error
        jw_httpsrv_destroy(httpsrv);
        _init_cb_data(&cb_data, evbase);
        cb_data.expected_status = 0;
        fct_chk(_send_and_loop(conn, url, body, evbase, NULL));
        fct_req(0 < cb_data.response_record.num_calls);
        fct_chk(cb_data.expected_status_matched);
        fct_req(!_test_get_timed_out());

        jw_dom_context_destroy(dom_ctx);
        _bosh_conn_destroy(conn);
        _bosh_conn_context_destroy(conn_ctx);
        free(url);
        _test_cleanup(evbase, failsafeEvent, NULL, NULL, NULL);
    } FCT_TEST_END()
} FCTMF_FIXTURE_SUITE_END()

#endif
