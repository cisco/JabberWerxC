/**
 * \file
 *
 * There are complex asynchronous interactions in this class.  In order to avoid
 * the situation where a callback is scheduled, but by the time it is fired,
 * the required objects have been deleted, the following pattern must be
 * consistently followed:
 *   1) The first thing a entrypoint or callback must do is check the stream
 *      state.  If the state is not as expected, the callback must return
 *      immediately.
 *   2) Objects that are potentially accessed in a callback must not be
 *      destroyed directly in an entrypoint call.  Instead, state must be set
 *      and a callback must be enqueued for the actual object destruction.
 *
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

#include <assert.h>
#include <string.h>
#include <jabberwerx/stream.h>
#include <jabberwerx/util/log.h>

#ifndef JABBERWERX_NO_BOSH

#include <stdlib.h>
#include <event2/http.h>
#include <jabberwerx/util/str.h>
#include "../include/stream_int.h"
#include "../include/bosh_conn_int.h"


#define MS_PER_SECOND      1000
#define MS_PER_USEC        1000
#define MAX_RETRY_ATTEMPTS 3
#define WAIT_INITIAL_SECS  30
#define WAIT_PADDING_SECS  5
#define MAX_REQS           2

// if we are redirected, cache final url in the config under this key
#define CONFIG_CACHED_URL_ "_bosh_url"


/********************************************
 * BOSH context information
 *******************************************/
typedef struct _bosh_ctx_int
{
    jw_stream *stream; // parent stream

    _bosh_conn_ctx bosh_conn_ctx; // context for _bosh_conn connections

    // +1 for a emergency "terminate" connection for when all others are busy
    _bosh_conn        connections[MAX_REQS+1];
    jw_dom_node *prev_bodies[MAX_REQS+1];

    jw_dom_node   *cur_body;       // is appended to until it is sent
    jw_workq_item *long_poll_item; // minimizes use of empty long poll reqs

    uint16_t retries;   // how many times we have retried the last operation
    uint16_t wait_secs; // response timeout (value set by server on open)

    // cur request id; incremented for each message sent. must never exceed
    // 9007199254740991 (0x1fffffffffffff), though this is not enforced here
    uint64_t rid;
} *_bosh_ctx;


/********************************************
 * utility functions
 *******************************************/

// assumes a variable named "stream" of the appropriate type has been defined
#define PUSH_BOSH_NDC int _ndcDepth = _push_bosh_ndc(stream, __func__)
#define POP_BOSH_NDC jw_log_pop_ndc(_ndcDepth)
static int _push_bosh_ndc(jw_stream *stream, const char *entrypoint)
{
    assert(entrypoint);

    char *label = "";
    if (stream && stream->config)
    {
        char *configLabel = jw_htable_get(stream->config,
                                          JW_STREAM_CONFIG_LOG_LABEL);
        if (configLabel)
        {
            label = configLabel;
        }
    }

    return jw_log_push_ndc("bosh stream=%p; label=%s; state=%s; entrypoint=%s",
            (void *)stream, label, _jw_stream_state_to_str(stream), entrypoint);
}

// *elems is NULL if there are no children.  otherwise it is a NULL-terminated
// array of children.  the array, if allocated, must be freed by the caller.
static bool _get_children_array(jw_stream     *stream,
                                jw_dom_node   *body,
                                jw_dom_node ***elems,
                                jw_err        *err)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(elems);

    size_t size = 0;
    jw_dom_node *elem = jw_dom_get_first_child(body);
    *elems = NULL;
    while (elem)
    {
        if (JW_DOM_TYPE_ELEMENT == jw_dom_get_nodetype(elem))
        {
            // check for stream errors
            if (0 == jw_strcmp(jw_dom_get_ename(elem), JW_STREAM_ENAME_ERROR))
            {
                jw_log_dom(JW_LOG_WARN, elem, "received xmpp error: ");
                assert(!stream->error_dom);

                // make sure we can keep it
                if (!jw_dom_context_retain(jw_dom_get_context(elem), err))
                {
                    return false;
                }
                stream->error_dom = elem;

                // nothing after error matters
                break;
            }

            ++size;
        }

        elem = jw_dom_get_sibling(elem);
    }

    if (size)
    {
        *elems = jw_data_malloc(sizeof(jw_dom_node*)*(size+1));
        if (!*elems)
        {
            jw_log(JW_LOG_WARN, "could not allocate element array");
            JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
            return false;
        }

        jw_dom_node **elemArr = *elems;
        elem = jw_dom_get_first_child(body);
        size_t i = 0;
        while (i < size)
        {
            if (JW_DOM_TYPE_ELEMENT == jw_dom_get_nodetype(elem))
            {
                elemArr[i] = elem;
                elem = jw_dom_get_sibling(elem);
                ++i;
            }
        }

        elemArr[size] = NULL;
    }

    return true;
}

static bool _create_body(jw_stream    *stream,
                         jw_dom_ctx   *dom_ctx,
                         jw_dom_node **dom,
                         jw_err            *err)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(stream);
    assert(dom_ctx);
    assert(dom);

    jw_dom_node *body = NULL;
    if (!jw_dom_element_create(dom_ctx,
                               "{http://jabber.org/protocol/httpbind}body",
                               &body,
                               err))
    {
        jw_log_err(JW_LOG_WARN, err, "could not create body");
        return false;
    }

    const char *sid = jw_stream_get_stream_id(stream);
    if (sid)
    {
        if (!jw_dom_set_attribute(body, "{}sid", sid, err))
        {
            jw_log(JW_LOG_WARN, "could not set sid");
            return false;
        }
    }

    _bosh_ctx bosh_ctx = stream->data;
    assert(bosh_ctx);
    unsigned long rid = ++bosh_ctx->rid;

    const int size = snprintf(NULL, 0, "%lu", rid);
    // I can't imagine why this would fail, but it's bad news if it does
    assert(0 <= size);
    char rid_str[size+1];
    snprintf(rid_str, size+1, "%lu", rid);

    if (!jw_dom_set_attribute(body, "{}rid", rid_str, err))
    {
        jw_log_err(JW_LOG_WARN, err, "could not set rid");
        return false;
    }

    *dom = body;
    return true;
}

static bool _save_attribute(jw_dom_node *body,
                            const char       *attrib,
                            jw_htable   *cfg,
                            const char       *key,
                            jw_err           *err)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    const char *attrib_value = jw_dom_get_attribute(body, attrib);
    if (attrib_value)
    {
        char *sid_cpy = jw_data_strdup(attrib_value);
        if (!sid_cpy)
        {
            jw_log(JW_LOG_WARN, "unable to copy %s", attrib);
            jw_dom_context_destroy(jw_dom_get_context(body));
            JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
            return false;
        }

        if (!jw_htable_put(cfg, key, sid_cpy, jw_htable_free_data_cleaner, err))
        {
            jw_log_err(JW_LOG_WARN, err, "failed to add '%s' to config", attrib);
            jw_dom_context_destroy(jw_dom_get_context(body));
            jw_data_free(sid_cpy);
            return false;
        }
    }

    return true;
}

static bool _check_redirect_uri(const char *prev, const char *next)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    // if old uri starts with http:, extra conditions apply
    if (0 == strncasecmp("http:", prev, 5))
    {
        // parse out URIs so we can get to their parts easily
        struct evhttp_uri *old_uri = evhttp_uri_parse(prev);
        if (NULL == old_uri)
        {
            jw_log(JW_LOG_WARN, "could not parse URI: '%s'", prev);
            return false;
        }

        struct evhttp_uri *new_uri = evhttp_uri_parse(next);
        if (NULL == new_uri)
        {
            jw_log(JW_LOG_WARN, "could not parse URI: '%s'", next);
            evhttp_uri_free(old_uri);
            return false;
        }

        // New URI must have the same scheme, host and port
        const char *new_scheme = evhttp_uri_get_scheme(new_uri);
        const char *old_host   = evhttp_uri_get_host(old_uri);
        const char *new_host   = evhttp_uri_get_host(new_uri);
        int         old_port   = evhttp_uri_get_port(old_uri);
        int         new_port   = evhttp_uri_get_port(new_uri);

        // Since this is 'http' we'll assume no port set
        // is port '80'
        old_port = (-1 == old_port) ? 80 : old_port;
        new_port = (-1 == new_port) ? 80 : new_port;

        if (!(new_scheme && 0 == strcasecmp(new_scheme, "http"))
         || !(new_host   && 0 == strcasecmp(old_host, new_host))
         || old_port != new_port)
        {
            jw_log(JW_LOG_DEBUG,
                   "redirected HTTP URI must only differ by path; cannot"
                   " redirect from '%s' to '%s'", prev, next);
            evhttp_uri_free(old_uri);
            evhttp_uri_free(new_uri);
            return false;
        }

        evhttp_uri_free(old_uri);
        evhttp_uri_free(new_uri);
    }

    // Assume old scheme is https. Anything goes.
    return true;
}


/********************************************
 * error/cleanup functions
 *******************************************/

static void _stream_destroyed_cb_result(jw_event_data evt,
                                        bool result, void *arg)
{
    UNUSED_PARAM(evt);
    UNUSED_PARAM(result);

    jw_stream *stream = arg;

    PUSH_BOSH_NDC;
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(stream);
    assert(!stream->destroy_trigger_data);

    if (stream->data)
    {
        _bosh_ctx bosh_ctx = stream->data;

        // ensure it's all clean
        assert(!bosh_ctx->bosh_conn_ctx);
        assert(!bosh_ctx->cur_body);

        if (bosh_ctx->long_poll_item)
        {
            jw_workq_item_destroy(bosh_ctx->long_poll_item);
            bosh_ctx->long_poll_item = NULL;
        }

        for (int conn_idx = 0; MAX_REQS >= conn_idx; ++conn_idx)
        {
            assert(!bosh_ctx->connections[conn_idx]);
            assert(!bosh_ctx->prev_bodies[conn_idx]);
        }

        // free it up
        jw_data_free(stream->data);
        stream->data = NULL;
    }

    _jw_stream_clean_error_dom(stream);

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

    jw_data_free(stream);

    POP_BOSH_NDC;
}

static void _reset_bosh(jw_stream *stream)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(stream);
    jw_htable *cfg = stream->config;
    if (cfg)
    {
        jw_htable_remove(cfg, JW_STREAM_CONFIG_STREAM_ID_);
        jw_htable_remove(cfg, CONFIG_CACHED_URL_);
    }

    _bosh_ctx bosh_ctx = stream->data;
    assert(bosh_ctx);

    if (bosh_ctx->cur_body)
    {
        jw_dom_context_destroy(jw_dom_get_context(bosh_ctx->cur_body));
        bosh_ctx->cur_body = NULL;
    }

    jw_workq_item_cancel(bosh_ctx->long_poll_item);

    if (stream->close_trigger_data)
    {
        jw_event_unprepare_trigger(stream->close_trigger_data);
        stream->close_trigger_data = NULL;
    }

    if (bosh_ctx->bosh_conn_ctx)
    {
        for (int i = 0; i <= MAX_REQS; ++i)
        {
            if (bosh_ctx->prev_bodies[i])
            {
                jw_dom_context_destroy(
                        jw_dom_get_context(bosh_ctx->prev_bodies[i]));
                bosh_ctx->prev_bodies[i] = NULL;
            }

            if (bosh_ctx->connections[i])
            {
                _bosh_conn_destroy(bosh_ctx->connections[i]);
            }
            bosh_ctx->connections[i] = NULL;
        }

        _bosh_conn_context_destroy(bosh_ctx->bosh_conn_ctx);
        bosh_ctx->bosh_conn_ctx = NULL;
    }
}

static void _finish_disconnect_cb(jw_workq_item *item, void *arg)
{
    UNUSED_PARAM(item);

    jw_stream *stream = arg;

    PUSH_BOSH_NDC;
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(stream);
    assert(STATE_STREAM_CLOSING == stream->state);
    assert(stream->close_event);
    assert(stream->close_event == item);
    assert(stream->close_trigger_data);

    _bosh_ctx bosh_ctx = stream->data;
    assert(bosh_ctx);

    bosh_ctx->retries = 0;

    jw_log(JW_LOG_DEBUG, "stream closed");

    jw_event *evt = jw_stream_event(stream, JW_STREAM_EVENT_CLOSED);
    jw_event_trigger_data *triggerData = stream->close_trigger_data;
    stream->close_trigger_data = NULL;

    _reset_bosh(stream);

    jw_event_trigger_prepared(evt, stream->error_dom,
                              _reset_state_result_cb, NULL, triggerData);
    POP_BOSH_NDC;
}

/*
 * Passing in jw_errcode for the purpose of setting the stream:error on the
 * stream structure.
 *
 * Semantically JW_ERR_NONE means one of two things, preserve the already
 * set stream->error_dom field, or there is no error to set.  Either way the
 * stream->error_dom field will remain untouched by passing JW_ERR_NONE.
 */
static void _finish_disconnect(jw_stream *stream, jw_errcode code)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(stream);
    stream->state = STATE_STREAM_CLOSING;
    _jw_stream_set_error_node_if_not_set(stream, code, NULL);

    jw_err err;
    if (jw_workq_item_is_scheduled(stream->close_event))
    {
        jw_log(JW_LOG_DEBUG, "close already scheduled; skipping");
    }
    else
    {
        jw_log(JW_LOG_DEBUG, "scheduling stream close event");
        if (!jw_workq_item_append(stream->close_event, &err))
        {
            jw_log_err(JW_LOG_ERROR, &err,
                       "unexpected failure when appending item to work queue");
            assert(false);
        }
    }
}

static void _event_opened_result_cb(jw_event_data evt,
                                    bool          result,
                                    void         *data)
{
    UNUSED_PARAM(result);

    jw_stream *stream = evt->source;
    assert(stream);

    PUSH_BOSH_NDC;
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    jw_dom_node *body = data;
    assert(body);
    jw_dom_context_destroy(jw_dom_get_context(body));

    POP_BOSH_NDC;
}

static void _elem_event_send_result_cb(jw_event_data evt,
                                       bool          result,
                                       void         *data)
{
    UNUSED_PARAM(result);

    jw_stream *stream = evt->source;
    assert(stream);

    PUSH_BOSH_NDC;
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    jw_dom_node **elems = data;

    assert(elems);
    assert(elems[0]);

    // all elems share a context; we only need to destroy it once
    jw_dom_context_destroy(jw_dom_get_context(elems[0]));
    jw_data_free(elems);

    POP_BOSH_NDC;
}

static void _elem_event_recv_result_cb(jw_event_data evt,
                                       bool result,
                                       void *data)
{
    UNUSED_PARAM(result);

    jw_stream *stream = evt->source;
    assert(stream);

    PUSH_BOSH_NDC;
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    jw_dom_node **elems = data;
    if (elems[0])
    {
        jw_dom_context_destroy(jw_dom_get_context(elems[0]));
    }
    jw_data_free(elems);

    POP_BOSH_NDC;
}


/********************************************
 * core logic functions
 *******************************************/

// returns the index of the next available connection, or -1 on error or if no
// connection is available.  the emergency connection is only considered as an
// option if urgent is set.  If -1 is returned, err is set, but if it was just
// the case that no connections were available, err.code is set to JW_ERR_NONE.
// this function will create the connection at the returned index if it has not
// yet already been created.
static int _get_available_conn_idx(
        jw_stream *stream, bool urgent, jw_err *err)
{
    JW_LOG_TRACE_FUNCTION("urgent=%d", urgent);

    assert(stream);
    _bosh_ctx bosh_ctx = stream->data;
    assert(bosh_ctx);

    // favor the lowest-numbered connections so we don't spawn many idle
    // connections
    for (int idx = 0; MAX_REQS > idx; ++idx)
    {
        // lazily initialize new connections as needed
        if (NULL == bosh_ctx->connections[idx])
        {
            if (!_bosh_conn_create(bosh_ctx->bosh_conn_ctx,
                                   &bosh_ctx->connections[idx], err))
            {
                jw_log_err(JW_LOG_WARN, err, "could not create connection %d",
                           idx);
                return -1;
            }
        }

        if (!_bosh_conn_is_active(bosh_ctx->connections[idx]))
        {
            return idx;
        }
    }

    // if it is urgent, allocate (if not already allocated) and use the
    // emergency connection
    if (urgent)
    {
        if (NULL == bosh_ctx->connections[MAX_REQS])
        {
            if (!_bosh_conn_create(bosh_ctx->bosh_conn_ctx,
                                   &bosh_ctx->connections[MAX_REQS], err))
            {
                jw_log_err(JW_LOG_WARN, err,
                           "could not create emergency bosh connection");
                return -1;
            }
        }
        else if (_bosh_conn_is_active(bosh_ctx->connections[MAX_REQS]))
        {
            jw_log(JW_LOG_WARN, "emergency bosh connection in use;"
                                " enqueueing urgent stanza");
            JABBERWERX_ERROR(err, JW_ERR_NONE);
            return -1;
        }

        return MAX_REQS;
    }

    JABBERWERX_ERROR(err, JW_ERR_NONE);
    return -1;
}

// takes ownership of body, regardless of whether the function succeeds
static bool _send_request(jw_stream *stream,
                          jw_dom_node *body,
                          int connIdx,
                          bool isRetry,
                          jw_err *err)
{
    JW_LOG_TRACE_FUNCTION("connIdx=%d", connIdx);
    if (!isRetry)
    {
        jw_log_dom(JW_LOG_VERBOSE, body, "sent: ");
    }
    else
    {
        jw_log_dom(JW_LOG_DEBUG, body, "resending: ");
    }

    assert(stream);
    assert(0 <= connIdx);
    assert(MAX_REQS >= connIdx);

    _bosh_ctx bosh_ctx = stream->data;
    assert(bosh_ctx);
    if (bosh_ctx->prev_bodies[connIdx])
    {
        jw_dom_context_destroy(
                jw_dom_get_context(bosh_ctx->prev_bodies[connIdx]));
        bosh_ctx->prev_bodies[connIdx] = NULL;
    }

    jw_dom_node **elems = NULL;
    if (!isRetry && !_get_children_array(stream, body, &elems, err))
    {
        jw_log_err(JW_LOG_WARN, err, "could not retrieve element children");
        goto _send_request_fail_label;
    }

    if (!isRetry && elems)
    {
        // ensure elems are not freed before the event is handled
        if (!jw_dom_context_retain(jw_dom_get_context(body), err))
        {
            jw_log_err(JW_LOG_WARN, err, "failed to retain body context");
            goto _send_request_fail_label;
        }

        jw_event *evt = jw_stream_event(stream, JW_STREAM_EVENT_ELEMSENT);
        if (!jw_event_trigger(
                evt, elems, _elem_event_send_result_cb, elems, err))
        {
            // undo the retain above; the context will get fully destroyed
            // after the goto
            jw_dom_context_destroy(jw_dom_get_context(body));
            jw_log_err(JW_LOG_WARN, err, "failed to event 'EVENT ELEMSENT'");
            JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
            goto _send_request_fail_label;
        }

        // if we fail after this point, ensure we don't double-delete the elems
        // which have been passed to the elemsent event
        elems = NULL;
    }

    // use cached url, if not there, use CONFIG_URL
    const char *url = jw_htable_get(stream->config, CONFIG_CACHED_URL_);
    if (!url)
    {
        url = jw_htable_get(stream->config, JW_STREAM_CONFIG_URI);
        if (!url)
        {
            jw_log_err(JW_LOG_WARN, err, "connection uri not found in config");
            JABBERWERX_ERROR(err, JW_ERR_INVALID_STATE);
            goto _send_request_fail_label;
        }

        if (!jw_htable_put(stream->config, CONFIG_CACHED_URL_,
                           (char *)url, NULL, err))
        {
            jw_log(JW_LOG_WARN, "could not cache URI");
            goto _send_request_fail_label;
        }
    }

    if (!_bosh_conn_send_request(bosh_ctx->connections[connIdx],
                url, body, bosh_ctx->wait_secs * MS_PER_SECOND, connIdx, err))
    {
        jw_log_err(JW_LOG_WARN, err, "could not send request");
        goto _send_request_fail_label;
    }
    bosh_ctx->prev_bodies[connIdx] = body;

    return true;

_send_request_fail_label:
    if (elems)
    {
        jw_data_free(elems);
    }

    jw_dom_context_destroy(jw_dom_get_context(body));

    return false;
}

static void _retry_connection(jw_stream *stream, int prevConnIdx)
{
    JW_LOG_TRACE_FUNCTION("prevConnIdx=%d", prevConnIdx);

    assert(stream);
    _bosh_ctx bosh_ctx = stream->data;
    assert(bosh_ctx);

    jw_err err;
    err.code = JW_ERR_NONE;

    int connIdx = _get_available_conn_idx(stream, false, &err);

    if (0 <= connIdx && bosh_ctx->retries < MAX_RETRY_ATTEMPTS)
    {
        jw_log(JW_LOG_DEBUG, "retry attempt [%d]", bosh_ctx->retries+1);

        jw_dom_node *body = bosh_ctx->prev_bodies[prevConnIdx];

        if (NULL == body)
        {
            // reopen was called while we were away
            bosh_ctx->retries = 0;
            return;
        }

        bosh_ctx->prev_bodies[prevConnIdx] = NULL;
        bosh_ctx->retries++;

        jw_err err;
        if (!_send_request(stream, body, connIdx, true, &err))
        {
            jw_log_err(JW_LOG_WARN, &err, "unable to resend body");
            // _send_request frees body's context on failure
            _finish_disconnect(stream, err.code);
            return;
        }
    }
    else
    {
        jw_log(JW_LOG_DEBUG, "done retrying: quitting");

        if (JW_ERR_NONE == err.code)
        {
            err.code = JW_ERR_SOCKET_CONNECT;
        }

        _finish_disconnect(stream, err.code);
    }
}

static bool _jw_stream_bosh_send_conn(jw_stream   *stream,
                                      jw_dom_node *dom,
                                      int               connIdx,
                                      bool              terminate,
                                      jw_err           *err)
{
    JW_LOG_TRACE_FUNCTION("connIdx=%d", connIdx);

    if (STATE_STREAM_READY != stream->state)
    {
        jw_log_dom(JW_LOG_WARN, dom, "stream closing; not sending stanza: ");
        JABBERWERX_ERROR(err, JW_ERR_INVALID_STATE);
        return false;
    }

    _bosh_ctx bosh_ctx = stream->data;
    assert(bosh_ctx);
    if (!bosh_ctx->cur_body)
    {
        jw_dom_ctx *dom_ctx = NULL;
        if (!jw_dom_context_create(&dom_ctx, err))
        {
            if (dom)
            {
                jw_dom_context_destroy(jw_dom_get_context(dom));
            }
            return false;
        }

        jw_dom_node *body = NULL;
        if (!_create_body(stream, dom_ctx, &body, err))
        {
            if (dom)
            {
                jw_dom_context_destroy(jw_dom_get_context(dom));
            }
            jw_dom_context_destroy(dom_ctx);
            return false;
        }
        bosh_ctx->cur_body = body;
    }

    jw_dom_node *body = bosh_ctx->cur_body;
    if (dom)
    {
        jw_dom_node *dom_copy = NULL;
        if (!jw_dom_import(jw_dom_get_context(body),
                           dom,
                           true,
                           &dom_copy,
                           err))
        {
            jw_dom_context_destroy(jw_dom_get_context(dom));
            return false;
        }

        jw_dom_context_destroy(jw_dom_get_context(dom));

        if (!jw_dom_add_child(body, dom_copy, err))
        {
            jw_log_err(JW_LOG_WARN, err, "could not add child");
            return false;
        }
    }

    if (terminate)
    {
        if (!jw_dom_set_attribute(body, "{}type", "terminate", err))
        {
            jw_log_err(JW_LOG_WARN, err, "could not add 'terminate' attribute");
            return false;
        }
    }

    // if the connection index is not specified, try to find an available
    // connection
    if (0 > connIdx)
    {
        connIdx = _get_available_conn_idx(stream, false, err);
    }

    // if there is a connection free, send the body
    bool retVal = true;
    if (0 <= connIdx)
    {
        if (!_send_request(stream, body, connIdx, false, err))
        {
            // _send_request frees body's context on failure
            retVal = false;
        }

        bosh_ctx->cur_body = NULL;
    }
    else
    {
        jw_log(JW_LOG_DEBUG, "all connections busy; enqueueing stanza");
    }

    return retVal;
}

static bool _detect_terminate(jw_dom_node *body,
                              jw_stream   *stream,
                              int               connIdx)
{
    JW_LOG_TRACE_FUNCTION("connIdx=%d", connIdx);

    assert(stream);

    const char *terminate_attrib = jw_dom_get_attribute(body, "type");
    if (terminate_attrib && 0 == strcmp(terminate_attrib, "terminate"))
    {
        jw_log(JW_LOG_DEBUG, "received 'terminate' body");
        const char *cond_attrib = jw_dom_get_attribute(body, "condition");
        if (cond_attrib && 0 == strcmp(cond_attrib, "see-other-uri"))
        {
            jw_log(JW_LOG_DEBUG, "being redirected");
            jw_dom_node *uri_element =
                    jw_dom_get_first_element(body, "uri");
            if (uri_element)
            {
                const char *next_uri = jw_dom_get_first_text(uri_element);
                const char *prev_uri = (const char *)
                        jw_htable_get(stream->config, CONFIG_CACHED_URL_);
                assert(prev_uri);

                if (!_check_redirect_uri(prev_uri, next_uri))
                {
                    jw_log(JW_LOG_WARN, "redirect target URI is invalid");
                    _finish_disconnect(stream, JW_ERR_BAD_FORMAT);
                    return true;
                }

                char *uri = jw_data_strdup(next_uri);
                if (NULL == uri)
                {
                    jw_log(JW_LOG_WARN, "could not allocate URI");
                    _finish_disconnect(stream, JW_ERR_NO_MEMORY);
                    return true;
                }

                jw_err err;
                if (!jw_htable_put(stream->config, CONFIG_CACHED_URL_,
                                   uri, jw_htable_free_data_cleaner, &err))
                {
                    jw_log(JW_LOG_WARN, "could not store URI");
                    _finish_disconnect(stream, err.code);
                    return true;
                }

                _retry_connection(stream, connIdx);
            }
            else
            {
                jw_log(JW_LOG_WARN, "no 'uri' child element");
                _finish_disconnect(stream, JW_ERR_BAD_FORMAT);
            }
        }
        else
        {
            jw_log(JW_LOG_INFO, "XMPP server shut down the connection");
            _finish_disconnect(stream, JW_ERR_NONE);
        }

        return true;
    }

    return false;
}

static void _long_poll_cb(jw_workq_item *item, void *arg)
{
    UNUSED_PARAM(item);

    jw_stream *stream = arg;

    PUSH_BOSH_NDC;
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(stream);
    _bosh_ctx bosh_ctx = stream->data;
    assert(bosh_ctx);

    // if no connections are active, send an empty body long poll request
    if (0 == _bosh_conn_context_get_num_active(bosh_ctx->bosh_conn_ctx))
    {
        jw_err err;
        jw_log(JW_LOG_DEBUG, "initiating long poll request");
        if (!_jw_stream_bosh_send_conn(stream, NULL, -1, false, &err))
        {
            _finish_disconnect(stream, err.code);
        }
    }

    POP_BOSH_NDC;
}


/********************************************
 * bosh_conn callbacks
 *******************************************/

static void _bosh_on_response_cb(
        struct evbuffer *buf, int http_status, int req_arg, void *arg)
{
    jw_stream *stream   = arg;
    int             conn_idx = req_arg;
    PUSH_BOSH_NDC;
    JW_LOG_TRACE_FUNCTION("conn_idx=%d; http_status=%d", conn_idx, http_status);

    jw_err err;
    assert(stream);
    assert(0 <= conn_idx);

    if (STATE_STREAM_CLOSING == stream->state)
    {
        jw_log(JW_LOG_DEBUG, "stream closing");
        _finish_disconnect(stream, JW_ERR_NONE);
        goto _on_response_cb_done_label;
    }

    if (200 != http_status)
    {
        if (0 == http_status)
        {
            jw_log(JW_LOG_WARN,
                   "unable to connect to server or proxy; retrying");
        }
        else
        {
            jw_log(JW_LOG_WARN,
                   "server http error: [%d]; retrying", http_status);
        }
        _retry_connection(stream, conn_idx);
        goto _on_response_cb_done_label;
    }

    jw_log(JW_LOG_DEBUG, "processing BOSH response on conn %d", conn_idx);
    _log_evbuffer(JW_LOG_VERBOSE, buf, "rcvd");

    jw_dom_node *body;
    if (!jw_parse_xml_buffer(buf, &body, &err))
    {
        jw_log_err(JW_LOG_WARN, &err, "XML parse error");
        goto _on_response_cb_fail_label;
    }

    _bosh_ctx bosh_ctx = stream->data;
    assert(bosh_ctx);

    if (_detect_terminate(body, stream, conn_idx))
    {
        jw_dom_context_destroy(jw_dom_get_context(body));
        goto _on_response_cb_done_label;
    }

    bosh_ctx->retries = 0;
    if (bosh_ctx->prev_bodies[conn_idx])
    {
        jw_dom_context_destroy(
                jw_dom_get_context(bosh_ctx->prev_bodies[conn_idx]));
        bosh_ctx->prev_bodies[conn_idx] = NULL;
    }

    if (STATE_STREAM_READY != stream->state)
    {
        // initial connection handling
        jw_htable *cfg = stream->config;
        if (!_save_attribute(
                body, "sid", cfg, JW_STREAM_CONFIG_STREAM_ID_, &err))
        {
            jw_dom_context_destroy(jw_dom_get_context(body));
            goto _on_response_cb_fail_label;
        }

        const char *attrib_value = jw_dom_get_attribute(body, "wait");
        if (attrib_value)
        {
            int32_t wait = strtol(attrib_value, NULL, 10);
            if (wait < 0 || wait > UINT16_MAX)
            {
                jw_log(JW_LOG_WARN, "invalid/out of range wait time");
                jw_dom_context_destroy(jw_dom_get_context(body));
                JABBERWERX_ERROR(&err, JW_ERR_INVALID_STATE);
                goto _on_response_cb_fail_label;
            }

            bosh_ctx->wait_secs = (uint16_t)wait;
        }

        stream->state = STATE_STREAM_READY;
    }

    jw_dom_node *feat = jw_dom_get_first_child(body);
    if (feat
     && 0 == jw_strcmp(jw_dom_get_ename(feat), JW_STREAM_ENAME_FEATURES))
    {
        jw_event *evt = jw_stream_event(stream, JW_STREAM_EVENT_OPENED);
        if (!jw_event_trigger(evt, feat, _event_opened_result_cb, body, &err))
        {
            // jw_event_trigger only errors with JW_ERR_NO_MEMORY. for out of
            // memory errors we've already preallocated a node.  we assign this
            // to our stream error element to be picked up by _finish_disconnect
            jw_log_err(JW_LOG_WARN, &err, "failed to event 'EVENT OPENED'");
            jw_dom_context_destroy(jw_dom_get_context(body));
            JABBERWERX_ERROR(&err, JW_ERR_NO_MEMORY);
            goto _on_response_cb_fail_label;
        }
    }
    else
    {
        jw_dom_node **elems;
        if (!_get_children_array(stream, body, &elems, &err))
        {
            jw_log_err(JW_LOG_WARN, &err, "could not enumerate children");
            jw_dom_context_destroy(jw_dom_get_context(body));
            goto _on_response_cb_fail_label;
        }

        if (elems)
        {
            jw_event *evt =
                    jw_stream_event(stream, JW_STREAM_EVENT_ELEMRECV);
            if (!jw_event_trigger(
                    evt, elems, _elem_event_recv_result_cb, elems, &err))
            {
                jw_log_err(JW_LOG_WARN, &err,
                           "failed to event 'EVENT ELEMRECV'");
                jw_dom_context_destroy(jw_dom_get_context(body));
                jw_data_free(elems);
                goto _on_response_cb_fail_label;
            }
        }
        else if (stream->error_dom)
        {
            // If err_dom was set, ref count was incremented
            jw_dom_context_destroy(jw_dom_get_context(body));
            jw_log(JW_LOG_DEBUG, "stream is CLOSED");
            JABBERWERX_ERROR(&err, JW_ERR_NONE);
            goto _on_response_cb_fail_label;
        }
        else
        {
            jw_dom_context_destroy(jw_dom_get_context(body));
        }
    }

    // ensure a next long poll request gets sent if there isn't any other
    // explicit activity immediately forthcoming from the user
    jw_workq_item_cancel(bosh_ctx->long_poll_item);
    if (!jw_workq_item_append(bosh_ctx->long_poll_item, &err))
    {
        jw_log_err(JW_LOG_ERROR, &err,
                   "unexpected failure when appending item to work queue");
        assert(false);
    }

    goto _on_response_cb_done_label;
_on_response_cb_fail_label:
    _finish_disconnect(stream, err.code);
_on_response_cb_done_label:
    POP_BOSH_NDC;
}

static void _bosh_on_error_cb(jw_errcode errcode, void *arg)
{
    jw_stream *stream = arg;
    PUSH_BOSH_NDC;
    JW_LOG_TRACE_FUNCTION("errcode=%d", errcode);
    _finish_disconnect(stream, errcode);
    POP_BOSH_NDC;
}


/********************************************
 * Functions used directly by stream.
 * no need to assert(stream) -- it is done in base class
 *******************************************/
static void _jw_stream_bosh_destroy(jw_stream *stream)
{
    PUSH_BOSH_NDC;
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    if (stream->destroy_trigger_data)
    {
        jw_event_trigger_data *dtd = stream->destroy_trigger_data;
        stream->destroy_trigger_data = NULL;

        jw_event *evt;
        if (stream->dispatch &&
            NULL != (evt = jw_stream_event(stream, JW_STREAM_EVENT_DESTROYED)))
        {
            jw_event_trigger_prepared(evt, NULL, _stream_destroyed_cb_result,
                                      stream, dtd);
            goto _jw_stream_bosh_destroy_done_label;
        }
        else
        {
            jw_event_unprepare_trigger(dtd);
        }
    }

    _stream_destroyed_cb_result(NULL, false, stream);

_jw_stream_bosh_destroy_done_label:
    POP_BOSH_NDC;
}

static bool _jw_stream_bosh_open(jw_stream *stream,
                                 jw_htable *config,
                                 jw_err *err)
{
    PUSH_BOSH_NDC;
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(stream);
    assert(config);

    if (STATE_STREAM_INIT != stream->state)
    {
        JABBERWERX_ERROR(err, JW_ERR_INVALID_STATE);
        POP_BOSH_NDC;
        return false;
    }

    stream->config = config;

    _reset_bosh(stream);
    stream->base = jw_htable_get(stream->config, JW_STREAM_CONFIG_SELECTOR);

    // prepare for orderly shutdown
    if (!_prepare_for_disconnect(stream, _finish_disconnect_cb, err))
    {
        goto _jw_stream_bosh_open_fail_label;
    }

    _bosh_ctx bosh_ctx = stream->data;
    assert(bosh_ctx);

    bosh_ctx->stream = stream;
    if (!_bosh_conn_context_create(stream->base, MAX_REQS, _bosh_on_response_cb,
                                   _bosh_on_error_cb, stream,
                                   &bosh_ctx->bosh_conn_ctx, err))
    {
        goto _jw_stream_bosh_open_fail_label;
    }
    _bosh_conn_context_set_label(bosh_ctx->bosh_conn_ctx,
                jw_htable_get(stream->config, JW_STREAM_CONFIG_LOG_LABEL));

    bosh_ctx->retries   = 0;
    bosh_ctx->wait_secs = WAIT_INITIAL_SECS;

    // initialize a first connection
    int conn_idx;
    if (0 > (conn_idx = _get_available_conn_idx(stream, false, err)))
    {
        goto _jw_stream_bosh_open_fail_label;
    }

    // use an unsigned int to ensure the starting request id is random, but
    // on the low end of its 53-bit namespace so it has room to grow
    uint32_t initial_rid;
    evutil_secure_rng_get_bytes(&initial_rid, sizeof(initial_rid));
    bosh_ctx->rid = initial_rid;

    jw_dom_ctx *dom_ctx = NULL;
    if (!jw_dom_context_create(&dom_ctx, err))
    {
        jw_log_err(JW_LOG_WARN, err, "could not create open body context");
        goto _jw_stream_bosh_open_fail_label;
    }

    jw_dom_node *body = NULL;
    if (!_create_body(stream, dom_ctx, &body, err))
    {
        jw_log_err(JW_LOG_WARN, err, "could not create open stream body");
        jw_dom_context_destroy(dom_ctx);
        goto _jw_stream_bosh_open_fail_label;
    }

    if (!jw_dom_put_namespace(body, "xmpp", "urn:xmpp:xbosh", err))
    {
        jw_log_err(JW_LOG_WARN, err,
                   "Could not put namespace 'xmpp' in open stream body");
        jw_dom_context_destroy(dom_ctx);
        goto _jw_stream_bosh_open_fail_label;
    }

    const char *domain = jw_stream_get_domain(stream);
    jw_log(JW_LOG_DEBUG, "domain: [%s]", domain);
    if (!jw_dom_set_attribute(body, "{}hold", "1", err) ||
        !jw_dom_set_attribute(body, "{}ver", "1.9", err) ||
        !jw_dom_set_attribute(body, "{}to", domain, err) ||
        !jw_dom_set_attribute(body, "{}wait", "30", err) ||
        !jw_dom_set_attribute(body, "{urn:xmpp:xbosh}version", "1.0", err))
    {
        jw_log_err(JW_LOG_WARN, err,
                   "couldn't set attributes for open stream body");
        jw_dom_context_destroy(dom_ctx);
        goto _jw_stream_bosh_open_fail_label;
    }

    if (!_send_request(stream, body, 0, false, err))
    {
        // _send_request frees body's context on failure
        goto _jw_stream_bosh_open_fail_label;
    }

    POP_BOSH_NDC;
    return true;

_jw_stream_bosh_open_fail_label:
    _reset_bosh(stream);
    POP_BOSH_NDC;
    return false;
}

static bool _jw_stream_bosh_reopen(jw_stream *stream,
                                   jw_err *err)
{
    PUSH_BOSH_NDC;
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    jw_err localErr;
    if (!err)
    {
        // ensure we have an error code to pass to _finish_disconnect()
        err = &localErr;
    }

    _bosh_ctx bosh_ctx = stream->data;
    assert(bosh_ctx);
    bosh_ctx->retries = 0;

    if (bosh_ctx->cur_body)
    {
        jw_dom_context_destroy(jw_dom_get_context(bosh_ctx->cur_body));
        bosh_ctx->cur_body = NULL;
    }
    for (int i = 0; i <= MAX_REQS; ++i)
    {
        if (bosh_ctx->prev_bodies[i])
        {
            jw_dom_context_destroy(jw_dom_get_context(bosh_ctx->prev_bodies[i]));
            bosh_ctx->prev_bodies[i] = NULL;
        }
    }

    jw_dom_ctx *dom_ctx = NULL;
    if (!jw_dom_context_create(&dom_ctx, err))
    {
        jw_log_err(JW_LOG_WARN, err, "could not create reopen body context");
        goto _jw_stream_bosh_reopen_fail_label;
    }

    jw_dom_node *body = NULL;
    if (!_create_body(stream, dom_ctx, &body, err))
    {
        jw_log_err(JW_LOG_WARN, err, "could not create reopen stream body");
        jw_dom_context_destroy(dom_ctx);
        goto _jw_stream_bosh_reopen_fail_label;
    }

    if (!jw_dom_put_namespace(body, "xmpp", "urn:xmpp:xbosh", err))
    {
        jw_log_err(JW_LOG_WARN, err,
                   "could not put namespace 'xmpp' in reopen stream body");
        jw_dom_context_destroy(dom_ctx);
        goto _jw_stream_bosh_reopen_fail_label;
    }

    const char *domain = jw_stream_get_domain(stream);
    if (!domain)
    {
        JABBERWERX_ERROR(err, JW_ERR_INVALID_ARG);
        jw_dom_context_destroy(dom_ctx);
        goto _jw_stream_bosh_reopen_fail_label;
    }

    if (!jw_dom_set_attribute(body, "{}to", domain, err) ||
        !jw_dom_set_attribute(body, "{urn:xmpp:xbosh}restart", "true", err))
    {
        jw_log_err(JW_LOG_WARN, err,
                   "could not set an attribute for reopen stream body");
        jw_dom_context_destroy(dom_ctx);
        goto _jw_stream_bosh_reopen_fail_label;
    }

    // if no available connection, initialize and use emergency connection
    int connIdx = _get_available_conn_idx(stream, true, err);
    if (0 > connIdx ||
        !_send_request(stream, body, connIdx, false, err))
    {
        // _send_request frees body's context on failure
        goto _jw_stream_bosh_reopen_fail_label;
    }

    POP_BOSH_NDC;
    return true;

_jw_stream_bosh_reopen_fail_label:
    _finish_disconnect(stream, err->code);
    POP_BOSH_NDC;
    return false;
}

static bool _jw_stream_bosh_send(jw_stream *stream,
                                 jw_dom_node *dom,
                                 jw_err *err)
{
    PUSH_BOSH_NDC;
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    bool retVal = _jw_stream_bosh_send_conn(stream, dom, -1, false, err);

    POP_BOSH_NDC;
    return retVal;
}

static void _jw_stream_bosh_close(jw_stream *stream, jw_errcode close_reason)
{
    PUSH_BOSH_NDC;
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    _bosh_ctx bosh_ctx = stream->data;
    if (bosh_ctx)
    {
        bosh_ctx->retries = 0;
        if (jw_stream_is_open(stream))
        {
            // ensure we have an err for the call below
            jw_err err = { .code = JW_ERR_NONE };

            // if no available connection, initialize and use emergency
            // connection
            int connIdx = _get_available_conn_idx(stream, true, &err);
            if (0 > connIdx ||
                !_jw_stream_bosh_send_conn(stream, NULL, connIdx, true, &err))
            {
                jw_log_err(JW_LOG_WARN, &err,
                           "unable to send 'terminate' body");

                if (JW_ERR_NONE == close_reason)
                {
                    close_reason = err.code;
                }

                _finish_disconnect(stream, close_reason);
                POP_BOSH_NDC;
                return;
            }
        }

        _jw_stream_set_error_node_if_not_set(stream, close_reason, NULL);
        stream->state = STATE_STREAM_CLOSING;
    }

    POP_BOSH_NDC;
}
#endif // ifndef JABBERWERX_NO_BOSH


/********************************************
 * Public API
 *******************************************/

JABBERWERX_API bool jw_stream_bosh_create(
                jw_workq *workq, jw_stream **retstream, jw_err *err)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(retstream);

#ifdef JABBERWERX_NO_BOSH
    UNUSED_PARAM(workq);
    JABBERWERX_ERROR(err, JW_ERR_NOT_IMPLEMENTED);
    return false;
#else
    jw_stream *stream = jw_data_calloc(1, sizeof(struct _jw_stream));
    if (!stream)
    {
        JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
        return false;
    }

    PUSH_BOSH_NDC;
    jw_log(JW_LOG_TRACE, "creating new bosh stream");

    // Build up function table
    (stream->func_table).jw_stream_destroy = _jw_stream_bosh_destroy;
    (stream->func_table).jw_stream_open    = _jw_stream_bosh_open;
    (stream->func_table).jw_stream_reopen  = _jw_stream_bosh_reopen;
    (stream->func_table).jw_stream_send    = _jw_stream_bosh_send;
    (stream->func_table).jw_stream_close   = _jw_stream_bosh_close;

    if (!_jw_stream_common_setup(stream, workq, err))
    {
        goto jw_stream_bosh_create_fail_label;
    }

    _bosh_ctx ctx = jw_data_calloc(1, sizeof(struct _bosh_ctx_int));
    if (ctx == NULL)
    {
        JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
        goto jw_stream_bosh_create_fail_label;
    }
    stream->data = ctx;

    if (!jw_workq_item_create(workq, _long_poll_cb, &ctx->long_poll_item, err))
    {
        jw_log_err(JW_LOG_WARN, err,
                   "failed to create workq item for long poll event");
        goto jw_stream_bosh_create_fail_label;
    }
    jw_workq_item_set_data(ctx->long_poll_item, stream, NULL);

    *retstream = stream;

    POP_BOSH_NDC;
    return true;

jw_stream_bosh_create_fail_label:
    if (stream->destroy_trigger_data)
    {
        jw_event_unprepare_trigger(stream->destroy_trigger_data);
        stream->destroy_trigger_data = NULL;
    }
    _stream_destroyed_cb_result(NULL, false, stream);
    POP_BOSH_NDC;
    return false;
#endif
}
