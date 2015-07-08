/**
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

#include <assert.h>
#include <string.h>

#include "mock_stream.h"
#include "../src/include/stream_int.h"
#include <jabberwerx/dom.h>
#include <event2/event.h>

static void _elems_event_result(jw_event_data evt, bool result, void *arg)
{
    UNUSED_PARAM(evt);
    UNUSED_PARAM(result);
    
    // behave like a real stream and clean up the elements!
    jw_dom_node **stanzas = arg;
    while (*stanzas != NULL)
    {
        jw_dom_ctx *ctx = jw_dom_get_context(*stanzas);
        jw_dom_context_destroy(ctx);
        ++stanzas;
    }
}

static void _jw_stream_mock_destroy(jw_stream *stream)
{
    if (stream->resource_error_dom)
    {
        jw_dom_context_destroy(jw_dom_get_context(stream->resource_error_dom));
        stream->resource_error_dom = NULL;
    }

    if (stream->dispatch)
    {
        jw_event_dispatcher_destroy(stream->dispatch);
        stream->dispatch = NULL;
    }

    _clean_disconnect_data(stream);
    jw_data_free(stream);
}

static bool _jw_stream_mock_open(jw_stream *stream,
                                 jw_htable *config,
                                 jw_err *err)
{
    assert(stream);
    assert(config);

    stream->config = config;
    stream->base = jw_htable_get(config, JW_STREAM_CONFIG_SELECTOR);
    stream->state = STATE_STREAM_READY;

    jw_dom_ctx *ctx = NULL;
    jw_dom_node *feats;
    bool ret = true;
    if (!jw_dom_context_create(&ctx, err)||
        !jw_dom_element_create(ctx, "{http://etherx.jabber.org/streams}features",
                               &feats, err) ||
        !jw_event_trigger(jw_stream_event(stream, JW_STREAM_EVENT_OPENED),
                          feats, NULL, NULL, err))
    {
        ret = false;
    }
    if (ctx)
    {
        jw_dom_context_destroy(ctx);
    }

    return ret;
}

static bool _jw_stream_mock_reopen(jw_stream *stream,
                                   jw_err *err)
{
    UNUSED_PARAM(stream);
    UNUSED_PARAM(err);
    return true;
}

static bool _jw_stream_mock_send(jw_stream *stream,
                                 jw_dom_node *dom,
                                 jw_err *err)
{
    jw_dom_node *stanzas[2];
    stanzas[0] = dom;
    stanzas[1] = NULL;

    if (!jw_event_trigger(jw_stream_event(stream, JW_STREAM_EVENT_ELEMSENT),
                          stanzas, _elems_event_result, stanzas, err))
    {
        return false;
    }

    return true;
}

static void _jw_stream_mock_close(jw_stream *stream, jw_errcode close_reason)
{
    UNUSED_PARAM(close_reason);
    
    stream->state = STATE_STREAM_INIT;

    jw_event_trigger(jw_stream_event(stream, JW_STREAM_EVENT_CLOSED),
                     NULL, NULL, NULL, NULL);
}

static void _read_stream_mock_cb(struct bufferevent *bev, void *arg)
{
    UNUSED_PARAM(bev);
    UNUSED_PARAM(arg);
}

static void _write_stream_mock_cb(struct bufferevent *bev, void *arg)
{
    UNUSED_PARAM(bev);
    UNUSED_PARAM(arg);
}

static void _connect_stream_mock_cb(struct bufferevent *bev,
                                    short events,
                                    void *arg)
{
    UNUSED_PARAM(bev);
    UNUSED_PARAM(events);
    UNUSED_PARAM(arg);
}

JABBERWERX_API bool jw_stream_mock_create(jw_workq   *workq,
                                          jw_stream **stream,
                                          jw_err    *err)
{
    assert(workq);
    assert(stream);

    jw_stream *newStream;

    newStream = jw_data_malloc(sizeof(struct _jw_stream));
    if (!newStream)
    {
        JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
        return false;
    }
    memset(newStream, 0, sizeof(struct _jw_stream));

    // Build up function table
    (newStream->func_table).jw_stream_destroy = _jw_stream_mock_destroy;
    (newStream->func_table).jw_stream_open    = _jw_stream_mock_open;
    (newStream->func_table).jw_stream_reopen  = _jw_stream_mock_reopen;
    (newStream->func_table).jw_stream_send    = _jw_stream_mock_send;
    (newStream->func_table).jw_stream_close   = _jw_stream_mock_close;

    (newStream->func_table).read_cb    = _read_stream_mock_cb;
    (newStream->func_table).write_cb   = _write_stream_mock_cb;
    (newStream->func_table).connect_cb = _connect_stream_mock_cb;

    if (!_jw_stream_common_setup(newStream, workq, err))
    {
        jw_stream_destroy(newStream);
        return false;
    }

    *stream = newStream;
    return true;
}

JABBERWERX_API bool jw_stream_mock_receive(jw_stream   *stream,
                                           jw_dom_node *stanza,
                                           jw_err      *err)
{
    jw_dom_node *stanzas[2];
    stanzas[0] = stanza;
    stanzas[1] = NULL;

    if (!jw_event_trigger(jw_stream_event(stream, JW_STREAM_EVENT_ELEMRECV),
                          stanzas, _elems_event_result, stanzas, err))
    {
        return false;
    }
    return true;
}
