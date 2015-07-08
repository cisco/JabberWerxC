/**
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

#include <assert.h>
#include <string.h>

#include "stanza_defines.h"
#include "fct.h"
#include "test_utils.h"

#include <jabberwerx/tracker.h>
#include <jabberwerx/dom.h>
#include <jabberwerx/util/str.h>

#include <event2/event.h>

struct _tracker_cb_data
{
    jw_dom_node *result;
    size_t      call_count;
};

static void _tracker_cb(jw_dom_node *result, void *user_data)
{
    struct _tracker_cb_data *data = (struct _tracker_cb_data*)user_data;
    data->result = result;
    ++data->call_count;
}

//create a simple iq/query
static jw_dom_node *_new_request(jw_dom_node *ctx_node)
{
    jw_dom_ctx  *ctx;
    jw_dom_node *query;
    jw_dom_node *request;

    if (ctx_node)
    {
        ctx = jw_dom_get_context(ctx_node);
    }
    else if (!jw_dom_context_create(&ctx, NULL))
    {
        return NULL;
    }
    if (!jw_dom_element_create(ctx, "{}iq", &request, NULL) ||
        !jw_dom_set_attribute(request, "{}to", "foo@example.com", NULL) ||
        !jw_dom_set_attribute(request, "{}from", "bar@example.com", NULL) ||
        !jw_dom_set_attribute(request, "{}type", "get", NULL) ||
        !jw_dom_element_create(ctx,
                               "{http://jabber.org/protocol/disco#info}query",
                               &query,
                               NULL) ||
        !jw_dom_add_child(request, query, NULL))
    {
        return NULL;
    }
    return request;
}
//clone request, switch to/from and set type==result
static jw_dom_node *_new_result(jw_dom_node *request)
{
    //not checking dom function results as this is not testing DOM
    jw_dom_node *result;
    const char *to, *from;

    if (jw_dom_clone(request, true, &result, NULL))
    {
        to = jw_dom_get_attribute(request, "{}to");
        from = jw_dom_get_attribute(request, "{}from");

        if (to && from &&
            jw_dom_set_attribute(result, "{}to", from, NULL) &&
            jw_dom_set_attribute(result, "{}from", to, NULL) &&
            jw_dom_set_attribute(result, "{}type", "result", NULL))
        {
            return result;
        }
    }
    return NULL;
}

FCTMF_SUITE_BGN(tracker_test)
{
    FCT_TEST_BGN(jw_tracker_create)
    {
        jw_err err;
        jw_tracker *tracker;
        jw_dom_node *request;
        jw_dom_node *result;
        jw_event_dispatcher *dispatch;
        jw_event *event;
        struct _tracker_cb_data cb_data;

        struct event_base *evbase = event_base_new();
        fct_req(jw_event_dispatcher_create(
                        "tracker_test", NULL, &dispatch, NULL));
        fct_req(jw_event_dispatcher_create_event(dispatch,
                                                 "beforeIQreceived",
                                                 &event,
                                                 NULL));

        fct_req(jw_tracker_create(evbase, &tracker, &err));
        fct_req(jw_event_bind(event,
                              jw_tracker_get_callback(),
                              tracker,
                              NULL));

        request = _new_request(NULL);
        fct_req(request);

        fct_req(jw_tracker_track(tracker,
                                 request,
                                 _tracker_cb,
                                 &cb_data,
                                 30,
                                 &err));
        const char *id = jw_dom_get_attribute(request, "{}id");
        fct_chk(id != NULL);

        result = _new_result(request);
        fct_req(result);


        memset(&cb_data, 0, sizeof(struct _tracker_cb_data));
        //trigger fires beforeIQreceived synchronously
        fct_req(jw_event_trigger(event, result, NULL, NULL, NULL));
        fct_chk_eq_int(cb_data.call_count, 1);
        fct_chk(cb_data.result == result);
        cb_data.call_count = 0; // don't reset result, on purpose
        fct_req(jw_dom_set_attribute(result, "{}id", NULL, NULL));
        fct_req(jw_tracker_track(tracker,
                                 request,
                                 _tracker_cb,
                                 &cb_data,
                                 1,
                                 &err));

        // there should only be the timeout event.
        //once that fires, and is removed dispatch should return.
        (void)event_base_dispatch(evbase);
        fct_chk_eq_int(cb_data.call_count, 1);
        fct_chk(cb_data.result == NULL);

        // check for timeout when stream is closed
        cb_data.call_count = 0;
        fct_req(jw_dom_set_attribute(result, "{}id", NULL, NULL));
        fct_req(jw_tracker_track(tracker,
                                 request,
                                 _tracker_cb,
                                 &cb_data,
                                 1,
                                 &err));

        jw_tracker_clear(tracker);
        (void)event_base_dispatch(evbase);
        fct_chk_eq_int(cb_data.call_count, 1);
        fct_chk(cb_data.result == NULL);

        jw_event_dispatcher_destroy(dispatch);
        jw_dom_context_destroy(jw_dom_get_context(request));
        jw_tracker_destroy(tracker);

        //OOM creation
        OOM_SIMPLE_TEST(jw_tracker_create(evbase, &tracker, &err));
        jw_tracker_destroy(tracker);
        //repeat OOM test with NULL error for coverage, no need to destroy
        //tracker, using alloc count from OOM_SIMPLE_TEST
        OOM_TEST_INIT();
        OOM_TEST(NULL, jw_tracker_create(evbase, &tracker, NULL));

        event_base_free(evbase);
    } FCT_TEST_END()

    FCT_TEST_BGN(jw_tracker_track)
    {
        jw_err err;
        jw_tracker *tracker;
        jw_dom_node *request;
        jw_dom_node *result;
        jw_event_dispatcher *dispatch;
        jw_event *event;
        struct _tracker_cb_data cb_data;

        struct event_base *evbase = event_base_new();
        fct_req(jw_event_dispatcher_create(
                        "tracker_test", NULL, &dispatch, NULL));
        fct_req(jw_event_dispatcher_create_event(dispatch,
                                                 "beforeIQreceived",
                                                 &event,
                                                 NULL));
        fct_req(jw_tracker_create(evbase, &tracker, NULL));
        fct_req(jw_event_bind(event,
                              jw_tracker_get_callback(),
                              tracker,
                              NULL));

        //track with defined id
        request = _new_request(NULL);
        fct_req(request);
        fct_req(jw_dom_set_attribute(request, "{}id", "my-id", NULL));
        fct_req(jw_tracker_track(tracker,
                                 request,
                                 _tracker_cb,
                                 &cb_data,
                                 30,
                                 NULL));
        fct_chk(0 == jw_strcmp("my-id", jw_dom_get_attribute(request, "{}id")));
        jw_tracker_clear(tracker);
        jw_dom_context_destroy(jw_dom_get_context(request));

        request = _new_request(NULL);

        fct_req(request);
        //track with 0 timeout
        fct_req(jw_tracker_track(tracker,
                                 request,
                                 _tracker_cb,
                                 &cb_data,
                                 0,
                                 NULL));
        memset(&cb_data, 0, sizeof(struct _tracker_cb_data));

        result = _new_result(request);
        fct_req(result);

        //trigger with various results to walk packet matching code
        fct_req(jw_dom_set_attribute(result, "{}from", NULL, NULL));
        fct_req(jw_event_trigger(event, result, NULL, NULL, NULL));
        fct_chk_eq_int(cb_data.call_count, 0);
        fct_chk(NULL == cb_data.result);

        result = _new_result(request);
        fct_req(result);
        fct_req(jw_dom_set_attribute(result, "{}id", NULL, NULL));
        fct_req(jw_event_trigger(event, result, NULL, NULL, NULL));
        fct_chk_eq_int(cb_data.call_count, 0);
        fct_chk(NULL == cb_data.result);

        result = _new_result(request);
        fct_req(result);
        fct_req(jw_dom_set_attribute(result, "{}type", NULL, NULL));
        fct_req(jw_event_trigger(event, result, NULL, NULL, NULL));
        fct_chk_eq_int(cb_data.call_count, 0);
        fct_chk(NULL == cb_data.result);

        result = _new_result(request);
        fct_req(result);
        fct_req(jw_dom_set_attribute(result, "{}type", "set", NULL));
        fct_req(jw_event_trigger(event, result, NULL, NULL, NULL));
        fct_chk_eq_int(cb_data.call_count, 0);
        fct_chk(NULL == cb_data.result);

        jw_tracker_clear(tracker);
        fct_chk_eq_int(cb_data.call_count, 1);
        fct_chk(NULL == cb_data.result);

        jw_dom_context_destroy(jw_dom_get_context(request));

        // to do OOM from within beforeIQReceived event handler, OOM macros
        // don't currently allow testing of event handlers.

        //OOM from within track
        request = _new_request(NULL);
        fct_req(request);
        OOM_RECORD_ALLOCS(jw_tracker_track(tracker,
                                           request,
                                           _tracker_cb,
                                           &cb_data,
                                           30,
                                           NULL));
        OOM_TEST_INIT();
            jw_tracker_clear(tracker);
            jw_dom_context_destroy(jw_dom_get_context(request));
            request = _new_request(NULL);
            fct_req(request);
        OOM_TEST(&err, jw_tracker_track(tracker,
                                        request,
                                        _tracker_cb,
                                        &cb_data,
                                        30,
                                        &err));
        //repeat with NULL error for coverage
        OOM_TEST_INIT();
            jw_tracker_clear(tracker);
            jw_dom_context_destroy(jw_dom_get_context(request));
            request = _new_request(NULL);
            fct_req(request);
        OOM_TEST(NULL, jw_tracker_track(tracker,
                                        request,
                                        _tracker_cb,
                                        &cb_data,
                                        30,
                                        NULL));

        jw_event_dispatcher_destroy(dispatch);
        jw_tracker_destroy(tracker);
        event_base_free(evbase);
        jw_dom_context_destroy(jw_dom_get_context(request));
    } FCT_TEST_END()
} FCTMF_SUITE_END()
