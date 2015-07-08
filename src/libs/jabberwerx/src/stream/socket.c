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
#include <jabberwerx/util/log.h>

#include "../include/dom_int.h"
#include "../include/stream_int.h"

#include <event2/event.h>
#include <event2/util.h>

#include <assert.h>
#include <string.h>
#include <stdint.h>
#include <netdb.h>
#include <limits.h>


#define DEFAULT_NODE_QUEUE_SIZE 500

static const char *JW_STREAM_CONFIG_SOCKADDR_ = "socketaddress";

// "raw" octet logging
static const jw_loglevel JW_STREAM_OCTECT_LOG_LEVEL_ = JW_LOG_DEBUG;


/**
 * state transition table setup
 */
typedef void (*_state_func)(jw_stream *stream);

static void _state_socket_resolve(jw_stream *stream);
static void _state_socket_connect(jw_stream *stream);
static void _state_stream_stream_out(jw_stream *stream);
static void _state_stream_stream_in(jw_stream *stream);
static void _state_stream_features_in(jw_stream *stream);
static void _state_stream_ready(jw_stream *stream);

static const _state_func STREAM_STATE_TABLE[] = {
    NULL,
    _state_socket_resolve,
    _state_socket_connect,
    _state_stream_stream_out,
    _state_stream_stream_in,
    _state_stream_features_in,
    _state_stream_ready,
    _state_stream_ready,
    NULL
};

/* multi-family socket end-point address
 * from: http://stackoverflow.com/questions/1429645/how-to-cast-sockaddr-storage-and-avoid-breaking-strict-aliasing-rules
 */
typedef union address
{
    struct sockaddr sa;
    struct sockaddr_in sa_in;
    struct sockaddr_in6 sa_in6;
    struct sockaddr_storage sa_stor;
}
address_t;

typedef struct _sockaddr_in
{
    int         size;
    address_t   address;
} jw_sockaddr_t;

typedef struct _socket_context_int
{
    jw_parser     *parser;
    jw_serializer *serializer;
    jw_dom_node   *root_dom;
    _jw_node_queue      input_doms;
    _jw_node_queue      output_doms;
    jw_timer      *timer;
    jw_workq_item *state_change_item;
} *_socket_context;


/********************************************
 * Utility functions
 *******************************************/
#define PUSH_SOCKET_NDC int _ndcDepth = _push_socket_ndc(stream, __func__)
#define POP_SOCKET_NDC jw_log_pop_ndc(_ndcDepth)
static int _push_socket_ndc(jw_stream *stream, const char *entrypoint)
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

    return jw_log_push_ndc("socket stream=%p; label=%s; entrypoint=%s",
                           (void *)stream, label, entrypoint);
}

static struct bufferevent * _get_custom_bufferevent(jw_htable *config)
{
    return jw_htable_get(config, JW_STREAM_CONFIG_BUFFEREVENT);
}

static void _clean_stream_pre_destroy_event(jw_stream*);
static void _reset_socket_result_cb(jw_event_data evt, bool result, void *arg)
{
    assert(evt);
    jw_stream *stream = evt->source;
    assert(stream);

    PUSH_SOCKET_NDC;
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    _clean_stream_pre_destroy_event(stream);
    _reset_state_result_cb(evt, result, arg);

    POP_SOCKET_NDC;
}

static void _close_event_cb(jw_workq_item *item, void *arg)
{
    UNUSED_PARAM(item);

    jw_stream *stream = arg;
    assert(stream);
    PUSH_SOCKET_NDC;
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(stream->close_trigger_data);
    assert(item);
    assert(stream->close_event == item);
    
    jw_workq_item_destroy(stream->close_event);
    stream->close_event = NULL;

    jw_log(JW_LOG_DEBUG, "stream closed");

    jw_event *evt = jw_stream_event(stream, JW_STREAM_EVENT_CLOSED);
    jw_event_trigger_data *triggerData = stream->close_trigger_data;
    stream->close_trigger_data = NULL;
    
    // this must be the last line that accesses stream since it might be
    // destroyed by the time jw_event_trigger_prepared returns
    jw_event_trigger_prepared(evt, stream->error_dom,
                              _reset_socket_result_cb, NULL, triggerData);

    POP_SOCKET_NDC;
}

/*
 * Passing in jw_errcode for the purpose of setting the stream:error on the
 * stream structure.
 *
 * Semantically JW_ERR_NONE means one of two things, preserve the already
 * set stream->_errorDOM field, or there is no error to set.  Either way the
 * stream->_errorDOM field will remain untouched by passing JW_ERR_NONE.
 */
static void _finish_disconnect(jw_stream *stream, jw_errcode code)
{
    JW_LOG_TRACE_FUNCTION("code=%d", code);

    assert(stream);
    assert(stream->close_event);

    if (jw_workq_item_is_scheduled(stream->close_event))
    {
        // we've already been through this
        return;
    }

    _jw_stream_set_error_node_if_not_set(stream, code, NULL);
    
    if (stream->bevent)
    {
        // ensure no more bufferevent callbacks are triggered
        // deferred callbacks can otherwise be triggered even after the
        // bufferevent is destroyed
        bufferevent_disable(stream->bevent, EV_READ|EV_WRITE|EV_TIMEOUT);
        bufferevent_setcb(stream->bevent, NULL, NULL, NULL, NULL);
    }

    jw_log(JW_LOG_DEBUG, "scheduling stream close event");
    
    // ensure the close event fires from the top of the libevent dispatch loop
    // so that no dependent structures (like the bufferevent) are in use when
    // they are destroyed
    jw_err err;
    if (!jw_workq_item_append(stream->close_event, &err))
    {
        jw_log_err(JW_LOG_ERROR, &err,
                   "unexpected failure when appending item to work queue");
        assert(false);
    }
}

static inline bool _node_queue_create(_jw_node_queue *q,
                                      size_t size,
                                      jw_err *err)
{
    JW_LOG_TRACE_FUNCTION("size=%zd", size);

    _jw_node_queue createdq = jw_data_malloc(sizeof(struct _jw_node_queue_int));
    if (!createdq)
    {
        jw_log(JW_LOG_WARN, "failed to allocate node queue");
        JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
        return false;
    }

    // +1 for terminating NULL element
    createdq->nodes = jw_data_calloc(size + 1, sizeof(jw_dom_node*));
    if (!createdq->nodes)
    {
        jw_data_free(createdq);
        jw_log(JW_LOG_WARN, "failed to allocate node queue array");
        JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
        return false;
    }
    createdq->size = size;
    createdq->index = 0;

    *q = createdq;
    return true;
}

static inline void _node_queue_destroy(_jw_node_queue q)
{
    JW_LOG_TRACE_FUNCTION("q=%p", (void *)q);

    // clean up nodes
    for (size_t idx = 0; NULL != q->nodes[idx]; ++idx)
    {
        jw_dom_context_destroy(jw_dom_get_context(q->nodes[idx]));
    }

    jw_data_free(q->nodes);
    jw_data_free(q);
}

static void _node_queue_cleanup_result_cb(jw_event_data evt,
                                          bool result, void *arg);
static bool _node_queue_event_and_reset(
        _jw_node_queue *q, jw_event *evt, bool sendArray, jw_err *err)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(q);
    assert(evt);
 
    _jw_node_queue     q_orig = *q;
    jw_dom_node **elems  = q_orig->nodes;

    if (!_node_queue_create(q, q_orig->size, err))
    {
        return false;
    }

    void *data;
    if (sendArray)
    {
        data = elems;
    }
    else
    {
        data = elems[0];
    }
    if (!jw_event_trigger(
            evt, data, _node_queue_cleanup_result_cb, q_orig, err))
    {
       _node_queue_destroy(q_orig);
       return false;
    }

    return true;
}

/* resets the parser/serializer/root element for (re)opening */
static void _reset_xml(_socket_context socket_ctx)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;
    assert(socket_ctx);

    if (socket_ctx->parser)
    {
        jw_parser_destroy(socket_ctx->parser);
        socket_ctx->parser = NULL;
    }

    if (socket_ctx->serializer)
    {
        // destroy serializer's evbuffer
        evbuffer_free(jw_serializer_get_output(socket_ctx->serializer));
        jw_serializer_destroy(socket_ctx->serializer);
        socket_ctx->serializer = NULL;
    }
    if (socket_ctx->root_dom)
    {
        jw_dom_ctx *ctx = jw_dom_get_context(socket_ctx->root_dom);
        jw_dom_context_destroy(ctx);
        socket_ctx->root_dom = NULL;
    }
}

static void _clean_stream_pre_destroy_event(jw_stream *stream)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(stream);
    
    _clean_disconnect_data(stream);
    _jw_stream_clean_error_dom(stream);

    if (stream->bevent)
    {
        // custom bufferevents are not owned by the stream
        if (!_get_custom_bufferevent(stream->config))
        {
            bufferevent_free(stream->bevent);
        }
        stream->bevent = NULL;
    }
    
    _socket_context socket_ctx = stream->data;
    if (NULL != socket_ctx)
    {
        _reset_xml(stream->data);

        if (socket_ctx->state_change_item)
        {
            jw_workq_item_destroy(socket_ctx->state_change_item);
            socket_ctx->state_change_item = NULL;
        }

        if (socket_ctx->input_doms)
        {
            _node_queue_destroy(socket_ctx->input_doms);
            socket_ctx->input_doms = NULL;
        }

        if (socket_ctx->output_doms)
        {
            _node_queue_destroy(socket_ctx->output_doms);
            socket_ctx->output_doms = NULL;
        }

        if (socket_ctx->timer)
        {
            jw_timer_destroy(socket_ctx->timer);
            socket_ctx->timer = NULL;
        }

        // free socket_ctx (aka stream->data)
        jw_data_free(stream->data);
        stream->data = NULL;
    }
}

static void _clean_stream_post_destroy_event(jw_stream *stream)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(stream);
    
    // these are not owned by the stream
    stream->base   = NULL;
    stream->config = NULL;
}

/* full-blown cleanup (minus dispatcher) */
static void _clean_stream(jw_stream *stream)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    _clean_stream_pre_destroy_event(stream);
    _clean_stream_post_destroy_event(stream);
}
/********************************************
 * End utility functions
 *******************************************/

/********************************************
 * Timer event callbacks
 *******************************************/
static void _keepalive_error_handler(jw_event_data event, void *arg)
{
    UNUSED_PARAM(event);
    jw_stream *stream = arg;
    assert(stream);

    PUSH_SOCKET_NDC;
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    _finish_disconnect(stream, JW_ERR_NO_MEMORY);

    POP_SOCKET_NDC;
}

static void _keepalive_handler(jw_event_data event, void *arg)
{
    UNUSED_PARAM(event);
    jw_stream *stream = arg;
    assert(stream);

    PUSH_SOCKET_NDC;
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    _socket_context socket_ctx = stream->data;
    assert(socket_ctx);

    // send a single space on the socket as a keepalive
    if (0 != evbuffer_add(bufferevent_get_output(stream->bevent), " ", 1))
    {
        _finish_disconnect(stream, JW_ERR_NO_MEMORY);
        POP_SOCKET_NDC;
        return;
    }

    jw_log(JW_LOG_VERBOSE, "sending whitespace keepalive");
    
    // reset timeout
    jw_timer_mark_activity(socket_ctx->timer);

    POP_SOCKET_NDC;
}
/********************************************
 * End timer event callbacks
 *******************************************/

/********************************************
 * Stream event callbacks
 *******************************************/
static void _node_queue_cleanup_result_cb(jw_event_data evt,
                                          bool result, void *arg)
{
    UNUSED_PARAM(result);

    assert(evt);
    jw_stream *stream = evt->source;
    assert(stream);

    PUSH_SOCKET_NDC;
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    _jw_node_queue node_queue = arg;
    assert(node_queue);

    _node_queue_destroy(node_queue);

    POP_SOCKET_NDC;
}

static void _stream_destroyed_result_cb(jw_event_data evt,
                                        bool result, void *arg)
{
    UNUSED_PARAM(evt);
    UNUSED_PARAM(result);

    jw_stream *stream = arg;
    assert(stream);

    PUSH_SOCKET_NDC;
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    if (stream->resource_error_dom)
    {
        jw_dom_ctx *ctx = jw_dom_get_context(stream->resource_error_dom);
        jw_dom_context_destroy(ctx);
        stream->resource_error_dom = NULL;
    }

    if (stream->dispatch)
    {
        jw_event_dispatcher_destroy(stream->dispatch);
        stream->dispatch = NULL;
    }

    _clean_stream_post_destroy_event(stream);
    jw_data_free(stream);

    POP_SOCKET_NDC;
}
/********************************************
 * End stream event callbacks
 *******************************************/

/********************************************
 * JW Parser callbacks
 *******************************************/
static bool _parse_enqueue(jw_stream *stream, jw_dom_node *elem)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(stream);
    _socket_context socket_ctx = stream->data;
    assert(socket_ctx);

    _jw_node_queue inq = socket_ctx->input_doms;

    assert(elem);
    assert(inq->index < inq->size);
    if (jw_dom_get_nodetype(elem) != JW_DOM_TYPE_ELEMENT)
    {
        // release and return
        jw_dom_context_destroy(jw_dom_get_context(elem));
        return false;
    }

    inq->nodes[inq->index++] = elem;

    if (strcmp(jw_dom_get_ename(elem), JW_STREAM_ENAME_ERROR) == 0)
    {
        jw_dom_ctx *errorCtx;
        jw_err err;
        if (!jw_dom_context_create(&errorCtx, &err))
        {
            _jw_stream_set_error_node_if_not_set(stream, err.code, NULL);
        }
        else
        {
            _jw_stream_clean_error_dom(stream);

            if (!jw_dom_import(errorCtx, elem, true, &stream->error_dom, &err))
            {
                // only failure is from out-of-memory
                jw_dom_context_destroy(errorCtx);
                _jw_stream_set_error_node_if_not_set(stream, err.code, NULL);
            }
        }

        return false;
    }
    return true;
}

static void _parser_opened(jw_event_data evt, void *arg)
{
    assert(evt);
    jw_dom_node *node = evt->data;
    jw_stream *stream = arg;
    assert(stream);
    jw_err err;

    PUSH_SOCKET_NDC;
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    if (node && !jw_dom_context_retain(jw_dom_get_context(node), &err))
    {
        jw_log_err(JW_LOG_ERROR, &err, "could not retain node context");
        assert(false);
    }

    if (_parse_enqueue(stream, node))
    {
        STREAM_STATE_TABLE[STATE_SOCKET_STREAM_IN](stream);
    }
    evt->handled = true;

    POP_SOCKET_NDC;
}

static void _parser_elem(jw_event_data evt, void *arg)
{
    assert(evt);
    jw_dom_node *node = evt->data;
    jw_stream *stream = arg;
    assert(stream);
    jw_err err;

    PUSH_SOCKET_NDC;
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    if (node && !jw_dom_context_retain(jw_dom_get_context(node), &err))
    {
        jw_log_err(JW_LOG_ERROR, &err, "could not retain node context");
        assert(false);
    }

    if (_parse_enqueue(stream, node))
    {
        STREAM_STATE_TABLE[stream->state](stream);
    }
    evt->handled = true;

    POP_SOCKET_NDC;
}

static void _parser_closed(jw_event_data evt, void *arg)
{
    jw_stream *stream = arg;
    assert(stream);
    
    PUSH_SOCKET_NDC;
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    _finish_disconnect(stream, JW_ERR_NONE);
    evt->handled = true;

    POP_SOCKET_NDC;
}
/********************************************
 * End JW Parser callbacks
 *******************************************/

/********************************************
 * Libevent callbacks
 *******************************************/
static void _read_stream_cb(struct bufferevent *bev, void *arg)
{
    jw_stream *stream = arg;
    assert(stream);

    PUSH_SOCKET_NDC;
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    struct evbuffer *input = bufferevent_get_input(bev);
    jw_err err;

    _socket_context socket_ctx = stream->data;
    assert(socket_ctx);
    assert(socket_ctx->input_doms);
    assert(input);

    _log_evbuffer(JW_LOG_VERBOSE, input, "rcvd");

    if (!socket_ctx->parser &&
        (!jw_parser_create(true, &(socket_ctx->parser), NULL) ||
        !jw_event_bind(jw_parser_event(socket_ctx->parser,
                                       JW_PARSER_EVENT_OPEN),
                        _parser_opened,
                        stream,
                        NULL) ||
        !jw_event_bind(jw_parser_event(socket_ctx->parser,
                                       JW_PARSER_EVENT_ELEMENT),
                        _parser_elem,
                        stream,
                        NULL) ||
        !jw_event_bind(jw_parser_event(socket_ctx->parser,
                                       JW_PARSER_EVENT_CLOSED),
                        _parser_closed,
                        stream,
                        NULL)))
    {
        /* jw_parser_create only errors with JW_ERR_NO_MEMORY
         * for out of memory errors we've preallocated a node.  assigning this
         * to our stream error element to be picked up by _finish_disconnect
         */
        err.code = JW_ERR_NO_MEMORY;
        goto _read_stream_cb_fail_label;
    }

    if (!jw_parser_process(socket_ctx->parser, input, &err))
    {
        goto _read_stream_cb_fail_label;
    }

    if (0 < socket_ctx->input_doms->index)
    {
        jw_event *evt = jw_stream_event(stream, JW_STREAM_EVENT_ELEMRECV);
        if (!_node_queue_event_and_reset(&socket_ctx->input_doms, evt, true, &err))
        {
            goto _read_stream_cb_fail_label;
        }
    }

    if (stream->error_dom != NULL)
    {
        err.code = JW_ERR_NONE;
        goto _read_stream_cb_fail_label;
    }
    
    goto _read_stream_cb_done_label;

_read_stream_cb_fail_label:
    _finish_disconnect(stream, err.code);
_read_stream_cb_done_label:
    POP_SOCKET_NDC;
}

static void _write_stream_cb(struct bufferevent *bev, void *arg)
{
    UNUSED_PARAM(bev);

    jw_stream *stream = arg;
    assert(stream);
    
    PUSH_SOCKET_NDC;
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    _socket_context socket_ctx = stream->data;
    assert(socket_ctx);
    _jw_node_queue outq = socket_ctx->output_doms;
    assert(outq);

    if (0 < outq->index)
    {
        jw_event *evt = jw_stream_event(stream, JW_STREAM_EVENT_ELEMSENT);
        jw_err   err;
        if (!_node_queue_event_and_reset(
                &socket_ctx->output_doms, evt, true, &err))
        {
            _finish_disconnect(stream, err.code);
            POP_SOCKET_NDC;
            return;
        }
    }

    POP_SOCKET_NDC;
}

static void _connect_stream_cb(struct bufferevent *bev,
                               short events,
                               void *arg)
{
    UNUSED_PARAM(bev);

    jw_stream *stream = arg;
    assert(stream);

    PUSH_SOCKET_NDC;
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    if (events & BEV_EVENT_CONNECTED)
    {
        /* We are connected. */
        STREAM_STATE_TABLE[STATE_SOCKET_STREAM_OUT](stream);
    }
    else if (events & (BEV_EVENT_ERROR|BEV_EVENT_EOF))
    {
        /* TODO examine libevent error and translate to xmpp stream:error
         * for now everything's going to be a remote-connection-failed
         */
        _finish_disconnect(stream, JW_ERR_SOCKET_CONNECT);
    }

    POP_SOCKET_NDC;
}
/********************************************
 * End libevent callbacks
 *******************************************/

/********************************************
 * Stream state functions/callbacks
 *******************************************/
static void _jw_stream_exec_state(jw_workq_item *item, void *arg)
{
    UNUSED_PARAM(item);

    jw_stream *stream = arg;
    assert(stream);
    PUSH_SOCKET_NDC;
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

#ifndef NDEBUG
    _socket_context socket_ctx = stream->data;
    assert(item);
    assert(socket_ctx);
    assert(item == socket_ctx->state_change_item);
#endif

    STREAM_STATE_TABLE[stream->state](stream);
    POP_SOCKET_NDC;
}

static bool _jw_stream_schedule_state(jw_stream *stream,
                                      bool initial,
                                      jw_err *err)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(stream);
    _socket_context socket_ctx = stream->data;
    assert(socket_ctx);
    jw_workq_item *item = socket_ctx->state_change_item;

    if (!item)
    {
        jw_workq *q = jw_event_dispatcher_get_workq(stream->dispatch);
        if (!jw_workq_item_create(q, _jw_stream_exec_state, &item, err))
        {
            jw_log_err(JW_LOG_WARN, err,
                       "could not create state exec work item");
            goto _jw_stream_schedule_state_fail_label;
        }

        jw_workq_item_set_data(item, stream, NULL);
        socket_ctx->state_change_item = item;
    }

    // schedule the event
    if (!jw_workq_item_append(item, err))
    {
        // should not ever fail
        jw_log_err(JW_LOG_ERROR, err,
                   "failed to schedule state exec work item");
        assert(false);
    }

    return true;

_jw_stream_schedule_state_fail_label:
    if (initial)
    {
        _clean_stream(stream);
    }
    else
    {
        _finish_disconnect(stream, err->code);
    }
    
    return false;
}

static void _state_socket_resolve(jw_stream *stream)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(stream);
    jw_err err;
    
    // prepare and store addrinfo
    jw_sockaddr_t *addr = jw_data_calloc(1, sizeof(jw_sockaddr_t));
    if (!addr)
    {
        _finish_disconnect(stream, JW_ERR_NO_MEMORY);
        return;
    }

    if (!jw_htable_put(stream->config,
                       JW_STREAM_CONFIG_SOCKADDR_,
                       addr,
                       jw_htable_free_data_cleaner,
                       &err))
    {
        jw_data_free(addr);
        _finish_disconnect(stream, err.code);
        return;
    }
    
    const char *hostname =
            (char *)jw_htable_get(stream->config, JW_STREAM_CONFIG_HOST);
    if (!hostname)
    {
        // fallback to domain
        hostname = (char *)jw_htable_get(stream->config,
                                         JW_STREAM_CONFIG_DOMAIN);
    }
    if (!hostname)
    {
        /* TODO discuss appropriate xmpp error to send, currently using
         * JW_ERR_INVALID_ARG which in turn sends internal-server-error
         */
        _finish_disconnect(stream, JW_ERR_INVALID_ARG);
        return;
    }

    const char *portstr =
            (char *)jw_htable_get(stream->config, JW_STREAM_CONFIG_PORT);
    if (!portstr)
    {
        /* TODO discuss appropriate xmpp error to send, currently using
         * JW_ERR_INVALID_ARG which in turn sends internal-server-error
         */
        _finish_disconnect(stream, JW_ERR_INVALID_ARG);
        return;
    }
    jw_log(JW_LOG_DEBUG, "connecting to %s on port %s", hostname, portstr);
    
    struct addrinfo *lookup = NULL;
    struct addrinfo hints;
    int             lookup_err;
    
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_flags = EVUTIL_AI_NUMERICHOST | EVUTIL_AI_NUMERICSERV;
    
    lookup_err = evutil_getaddrinfo(hostname, portstr, &hints, &lookup);
    if (EVUTIL_EAI_NONAME == lookup_err)
    {
        // try again, sans numeric hosts
        hints.ai_flags = EVUTIL_AI_NUMERICSERV;
        lookup_err = evutil_getaddrinfo(hostname, portstr, &hints, &lookup);
    }
    if (0 != lookup_err)
    {
        switch (lookup_err)
        {
            case EVUTIL_EAI_MEMORY:
                JABBERWERX_ERROR(&err, JW_ERR_NO_MEMORY);
                break;
            default:
                // treat every other error as invalid argument (for now)
                JABBERWERX_ERROR(&err, JW_ERR_INVALID_ARG);
                break;
        }
        _finish_disconnect(stream, err.code);
        return;
    }
    addr->size = lookup->ai_addrlen;
    memcpy(&addr->address, lookup->ai_addr, lookup->ai_addrlen);
    
    if (jw_log_get_level() == JW_LOG_DEBUG)
    {
        // log the resolved IP address
        char ip[INET6_ADDRSTRLEN];
        int  af = lookup->ai_family;
        void *sa = NULL;
        
        switch (af)
        {
            case AF_INET:
                sa = &addr->address.sa_in.sin_addr;
                break;
            case AF_INET6:
                sa = &addr->address.sa_in6.sin6_addr;
                break;
        }

        if (sa)
        {
            evutil_inet_ntop(af, sa, ip, INET6_ADDRSTRLEN);
            jw_log(JW_LOG_DEBUG, "resolved %s to %s", hostname, ip);
        }
    }
    
    evutil_freeaddrinfo(lookup);
    
    stream->state = STATE_SOCKET_CONNECT;
    _jw_stream_schedule_state(stream, false, &err);
}

static void _state_socket_connect(jw_stream *stream)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(stream);
    _socket_context socket_ctx = stream->data;
    assert(socket_ctx);

    struct bufferevent *custom_bevent = _get_custom_bufferevent(stream->config);
    if (custom_bevent)
    {
        stream->bevent = custom_bevent;
    }
    else
    {
        stream->bevent = bufferevent_socket_new(stream->base, -1,
                                                BEV_OPT_CLOSE_ON_FREE);
        if (!stream->bevent)
        {
            /* TODO discuss appropriate xmpp error to send, currently using
             * JW_ERR_INVALID_ARG which in turn sends internal-server-error
             */
            _finish_disconnect(stream, JW_ERR_INVALID_ARG);
            return;
        }
    }

    bufferevent_setcb(stream->bevent,
                      _read_stream_cb,
                      _write_stream_cb,
                      _connect_stream_cb,
                      stream);
    if (bufferevent_enable(stream->bevent, EV_READ|EV_WRITE) != 0)
    {
        /* TODO discuss appropriate xmpp error to send, currently using
         * JW_ERR_INVALID_ARG which in turn sends internal-server-error
         */
        _finish_disconnect(stream, JW_ERR_INVALID_ARG);
        return;
    }

    if (custom_bevent)
    {
        // custom bufferevents are assumed to be connected
        _connect_stream_cb(stream->bevent, BEV_EVENT_CONNECTED, stream);
    }
    else
    {
        jw_sockaddr_t *addr = jw_htable_get(stream->config,
                                            JW_STREAM_CONFIG_SOCKADDR_);
        assert(addr);

        if (bufferevent_socket_connect(stream->bevent,
                                       &(addr->address.sa),
                                       addr->size) < 0)
        {
            /* TODO discuss appropriate xmpp error to send, currently using
             * JW_ERR_INVALID_ARG which in turn sends internal-server-error
             */
            _finish_disconnect(stream, JW_ERR_INVALID_ARG);
            return;
        }
    }

    // start the keepalive timer
    jw_timer_mark_activity(socket_ctx->timer);
}

static void _state_stream_stream_out(jw_stream *stream)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(stream);
    _socket_context socket_ctx = stream->data;
    assert(socket_ctx);

    jw_dom_ctx *domCtx;
    jw_err err;

    _reset_xml(socket_ctx);
    _jw_stream_clean_error_dom(stream);

    if (!jw_dom_context_create(&domCtx, NULL))
    {
        /* jw_dom_context_create only errors with JW_ERR_NO_MEMORY
         * for out of memory errors we've preallocated a node.
         * assigning this to our stream error element to be picked up by
         * _finish_disconnect
         */
        _finish_disconnect(stream, JW_ERR_NO_MEMORY);
        return;
    }
    if (!jw_dom_element_create_int(domCtx,
                                   JW_STREAM_ENAME_STREAM,
                                   &socket_ctx->root_dom,
                                   &err))
    {
        jw_dom_context_destroy(domCtx);
        _finish_disconnect(stream, err.code);
        return;
    }
    if (!jw_dom_put_namespace_int(socket_ctx->root_dom,
                                  JW_STREAM_NAMESPACE_PREFIX,
                                  JW_STREAM_NAMESPACE_URI,
                                  &err))
    {
        _finish_disconnect(stream, err.code);
        return;
    }
    if (!jw_dom_put_namespace(socket_ctx->root_dom,
                              "",
                              jw_stream_get_namespace(stream),
                              &err))
    {
        _finish_disconnect(stream, err.code);
        return;
    }
    if (!jw_dom_set_attribute(socket_ctx->root_dom,
                              JW_STREAM_ATTR_TO,
                              jw_stream_get_domain(stream),
                              &err))
    {
        _finish_disconnect(stream, err.code);
        return;
    }
    if (!jw_dom_set_attribute_int(socket_ctx->root_dom,
                                  JW_STREAM_ATTR_VERSION,
                                  JW_STREAM_VERSION,
                                  &err))
    {
        _finish_disconnect(stream, err.code);
        return;
    }

    struct evbuffer *outbuff = evbuffer_new();
    if (!outbuff)
    {
        _finish_disconnect(stream, JW_ERR_NO_MEMORY);
        return;
    }

    if (!jw_serializer_create(outbuff, &socket_ctx->serializer, NULL))
    {
        /* jw_serializer_create only errors with JW_ERR_NO_MEMORY
         * for out of memory errors we've preallocated a node.
         * assigning this to our stream error element to be picked up by
         * _finish_disconnect
         */
        evbuffer_free(outbuff);
        _finish_disconnect(stream, JW_ERR_NO_MEMORY);
        return;
    }

    if (!jw_serializer_write_start(
            socket_ctx->serializer, socket_ctx->root_dom, &err))
    {
        _finish_disconnect(stream, err.code);
        return;
    }
    _log_evbuffer(JW_LOG_VERBOSE, outbuff, "sent");
    if (0 != evbuffer_add_buffer(bufferevent_get_output(stream->bevent),
                                 outbuff))
    {
        _finish_disconnect(stream, JW_ERR_NO_MEMORY);
        return;
    }

    // update keepalive timer
    jw_timer_mark_activity(socket_ctx->timer);

    stream->state = STATE_SOCKET_STREAM_IN;
}

static void _state_stream_stream_in(jw_stream *stream)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    jw_dom_node *root;
    jw_err            err;

    assert(stream);
    _socket_context socket_ctx = stream->data;
    assert(socket_ctx);
    _jw_node_queue inq = socket_ctx->input_doms;
    assert(inq);
    assert(inq->nodes);
    assert(0 < inq->index);
    
    /* TODO: grab DOM attributes */
    root = inq->nodes[0];
    assert(root != NULL);

    const char *id = jw_dom_get_attribute(root, JW_STREAM_ATTR_ID);
    if (!id)
    {
        /* bad server data! */
        /* TODO discuss appropriate xmpp error to send, currently using
         * JW_ERR_INVALID_ARG which in turn sends internal-server-error
         */
        _finish_disconnect(stream, JW_ERR_INVALID_ARG);
        return;
    }

    char *id_copy = jw_data_strdup(id);
    if (!id_copy)
    {
        _finish_disconnect(stream, JW_ERR_NO_MEMORY);
        return;
    }

    if (!jw_htable_put(stream->config,
                       JW_STREAM_CONFIG_STREAM_ID_,
                       (void *)id_copy,
                       jw_htable_free_data_cleaner,
                       &err))
    {
        jw_data_free(id_copy);
        _finish_disconnect(stream, err.code);
        return;
    }

    // cleanup inbound root and any other queued doms
    if (!_node_queue_create(&socket_ctx->input_doms, inq->size, &err))
    {
        _finish_disconnect(stream, err.code);
        return;
    }
    _node_queue_destroy(inq);

    stream->state = STATE_SOCKET_FEATURES_IN;
}

static void _state_stream_features_in(jw_stream *stream)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(stream);
    _socket_context socket_ctx = stream->data;
    assert(socket_ctx);
    _jw_node_queue inq = socket_ctx->input_doms;
    assert(inq);
    assert(inq->nodes);
    assert(0 < inq->index);
    
    jw_dom_node *feats = inq->nodes[0];
    assert(feats != NULL);

    jw_log_dom(JW_LOG_DEBUG, feats, "received features: ");

    if (0 != strcmp(jw_dom_get_ename(feats), JW_STREAM_ENAME_FEATURES))
    {
        /* TODO discuss appropriate xmpp error to send, currently using
         * JW_ERR_INVALID_ARG which in turn sends internal-server-error
         */
        _finish_disconnect(stream, JW_ERR_INVALID_ARG);
        return;
    }

    stream->state = STATE_STREAM_READY;

    jw_event *evt = jw_stream_event(stream, JW_STREAM_EVENT_OPENED);
    jw_err   err;
    if (!_node_queue_event_and_reset(&socket_ctx->input_doms, evt, false, &err))
    {
        _finish_disconnect(stream, err.code);
    }
}

static void _state_stream_ready(jw_stream *stream)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(stream);
    _socket_context socket_ctx = stream->data;
    assert(socket_ctx);
    _jw_node_queue inq = socket_ctx->input_doms;
    assert(inq);
    
    if (inq->index == inq->size)
    {
        jw_event *evt = jw_stream_event(stream, JW_STREAM_EVENT_ELEMRECV);
        jw_err         err;
        if (!_node_queue_event_and_reset(
                &socket_ctx->input_doms, evt, true, &err))
        {
            _finish_disconnect(stream, err.code);
        }
    }
}
/********************************************
 * End stream state functions/callbacks
 *******************************************/

/********************************************
 * Functions used directly by stream.
 * no need to assert(stream) -- it is done in base class
 *******************************************/
static void _jw_stream_socket_destroy(jw_stream *stream)
{
    PUSH_SOCKET_NDC;
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    if (stream->destroy_trigger_data)
    {
        _clean_stream_pre_destroy_event(stream);

        jw_event *evt;
        if (stream->dispatch &&
            (evt = jw_stream_event(stream, JW_STREAM_EVENT_DESTROYED)))
        {
            jw_event_trigger_prepared(evt, NULL, _stream_destroyed_result_cb,
                                      stream, stream->destroy_trigger_data);
        }
        else
        {
            if (stream->destroy_trigger_data)
            {
                jw_event_unprepare_trigger(stream->destroy_trigger_data);
            }

            _stream_destroyed_result_cb(NULL, false, stream);
        }
    }
    else
    {
        // if _destroyTriggerData isn't initialized, nothing else should be
        assert(!stream->dispatch);
        assert(!stream->resource_error_dom);
        jw_data_free(stream);
    }

    POP_SOCKET_NDC;
}

static bool _jw_stream_socket_open(jw_stream *stream,
                                   jw_htable *config,
                                   jw_err         *err)
{
    PUSH_SOCKET_NDC;
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(stream);
    assert(config);

    // return if not in initial state
    if (stream->state != STATE_STREAM_INIT)
    {
        jw_log(JW_LOG_WARN, "cannot open socket; not in initial state");
        JABBERWERX_ERROR(err, JW_ERR_INVALID_STATE);
        goto _jw_stream_socket_open_failed_label;
    }

    if (!_get_custom_bufferevent(config))
    {
        // check for required port config option
        if (!jw_htable_get(config, JW_STREAM_CONFIG_PORT))
        {
            jw_log(JW_LOG_WARN, "cannot open socket; port not configured");
            JABBERWERX_ERROR(err, JW_ERR_INVALID_ARG);
            goto _jw_stream_socket_open_failed_label;
        }
    }

    _clean_stream(stream);

    _socket_context socket_ctx =
            jw_data_malloc(sizeof(struct _socket_context_int));
    if (socket_ctx == NULL)
    {
        jw_log(JW_LOG_WARN, "cannot allocate socket context");
        JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
        goto _jw_stream_socket_open_failed_label;
    }
    memset(socket_ctx, 0, sizeof(struct _socket_context_int));
    stream->data = socket_ctx;

    struct event_base *eventBase =
            jw_htable_get(config, JW_STREAM_CONFIG_SELECTOR);
    
    // prepare for orderly shutdown
    if (!_prepare_for_disconnect(stream, _close_event_cb, err))
    {
        jw_log(JW_LOG_WARN, "cannot allocate disconnect data");
        goto _jw_stream_socket_open_failed_label;
    }
    
    stream->config = config;
    stream->base = eventBase;

    // setup state
    size_t qsize = (size_t)(uintptr_t)jw_htable_get(
            stream->config, JW_STREAM_CONFIG_QUEUE_SIZE);
    if (0 == qsize)
    {
        qsize = DEFAULT_NODE_QUEUE_SIZE;
    }
    jw_log(JW_LOG_DEBUG, "queue size: %zd", qsize);

    if (!_node_queue_create(&socket_ctx->input_doms, qsize, err)
     || !_node_queue_create(&socket_ctx->output_doms, qsize, err)
     || !jw_timer_create(jw_event_dispatcher_get_workq(stream->dispatch),
                         &socket_ctx->timer, err))
    {
        jw_log(JW_LOG_WARN, "cannot allocate node queues");
        goto _jw_stream_socket_open_failed_label;
    }

    jw_timer_set_inactivity_timeout(socket_ctx->timer,
                                    _get_keepalive_ms(stream));

    if (!jw_event_bind(jw_timer_event(socket_ctx->timer, JW_TIMER_EVENT_TIMEOUT),
                       _keepalive_handler, stream, err)
     || !jw_event_bind(jw_timer_event(socket_ctx->timer, JW_TIMER_EVENT_ERROR),
                       _keepalive_error_handler, stream, err))
    {
        jw_log(JW_LOG_WARN, "unable to bind socket events");
        goto _jw_stream_socket_open_failed_label;
    }

    stream->state = _get_custom_bufferevent(config) ?
                        STATE_SOCKET_CONNECT : STATE_SOCKET_RESOLVE;

    // progress to the next state!
    bool retval = _jw_stream_schedule_state(stream, true, err);

    POP_SOCKET_NDC;
    return retval;

_jw_stream_socket_open_failed_label:
    _clean_stream(stream);
    POP_SOCKET_NDC;
    return false;
}

static bool _jw_stream_socket_reopen(jw_stream *stream,
                                     jw_err *err)
{
    PUSH_SOCKET_NDC;
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    if (stream->state != STATE_STREAM_READY)
    {
        JABBERWERX_ERROR(err, JW_ERR_INVALID_STATE);
        POP_SOCKET_NDC;
        return false;
    }

    // TODO: the work!
    STREAM_STATE_TABLE[STATE_SOCKET_STREAM_OUT](stream);

    POP_SOCKET_NDC;
    return true;
}

static bool _jw_stream_socket_send(jw_stream *stream,
                                   jw_dom_node *dom,
                                   jw_err *err)
{
    PUSH_SOCKET_NDC;
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    if (!jw_stream_is_open(stream))
    {
        JABBERWERX_ERROR(err, JW_ERR_INVALID_STATE);
        goto _jw_stream_socket_send_fail_label;
    }

    assert(stream);
    assert(dom);
    _socket_context socket_ctx = stream->data;
    assert(socket_ctx);
    _jw_node_queue outq = socket_ctx->output_doms;
    assert(outq);
    assert(outq->nodes);

    if (outq->index == outq->size)
    {
        jw_log(JW_LOG_WARN, "cannot enqueue stanza; queue limit reached: %zd",
               outq->size);
        JABBERWERX_ERROR(err, JW_ERR_OVERFLOW);
        goto _jw_stream_socket_send_fail_label;
    }

    outq->nodes[outq->index++] = dom;
    jw_log_dom(JW_LOG_DEBUG, dom,
               "enqueued stanza at position %zd: ", outq->index);

    if (!jw_serializer_write(socket_ctx->serializer, dom, err))
    {
        outq->nodes[--outq->index] = NULL;
        goto _jw_stream_socket_send_fail_label;
    }
    _log_evbuffer(JW_LOG_VERBOSE,
                  jw_serializer_get_output(socket_ctx->serializer), "sent");
    if (0 != evbuffer_add_buffer(
            bufferevent_get_output(stream->bevent),
            jw_serializer_get_output(socket_ctx->serializer)))
    {
        JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
        goto _jw_stream_socket_send_fail_label;
    }

    // update keepalive timer
    jw_timer_mark_activity(socket_ctx->timer);

    POP_SOCKET_NDC;
    return true;

_jw_stream_socket_send_fail_label:
    jw_dom_context_destroy(jw_dom_get_context(dom));
    POP_SOCKET_NDC;
    return false;
}

static void _jw_stream_socket_close(jw_stream *stream, jw_errcode close_reason)
{
    PUSH_SOCKET_NDC;
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(stream);
    _socket_context socket_ctx = stream->data;
    assert(socket_ctx);

    jw_err err      = { .code = JW_ERR_NONE };
    bool   success  = false;
    
    jw_log(JW_LOG_DEBUG, "socket closing; current state=%d", stream->state);
    if (stream->state == STATE_STREAM_INIT)
    {
        success = true;
        goto _jw_stream_socket_close_done_label;
    }

    stream->state = STATE_STREAM_CLOSING;
    if (NULL == socket_ctx->serializer)
    {
        // we don't have a serializer, so nothing more we can do here
        success = true;
        goto _jw_stream_socket_close_done_label;
    }

    if (!jw_serializer_write_end(socket_ctx->serializer, &err))
    {
        goto _jw_stream_socket_close_done_label;
    }

    _log_evbuffer(JW_LOG_VERBOSE,
                  jw_serializer_get_output(socket_ctx->serializer), "sent");
    if (0 != evbuffer_add_buffer(
            bufferevent_get_output(stream->bevent),
            jw_serializer_get_output(socket_ctx->serializer)))
    {
        JABBERWERX_ERROR(&err, JW_ERR_NO_MEMORY);
        goto _jw_stream_socket_close_done_label;
    }
    
    success = true;

_jw_stream_socket_close_done_label:
    if (!success)
    {
        if (JW_ERR_NONE == close_reason)
        {
            close_reason = err.code;
        }

        _finish_disconnect(stream, close_reason);
    }
    POP_SOCKET_NDC;
}

JABBERWERX_API bool jw_stream_socket_create(jw_workq   *workq,
                                            jw_stream **retstream,
                                            jw_err          *err)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;
    
    assert(retstream);

    jw_stream *stream = jw_data_malloc(sizeof(struct _jw_stream));
    if (!stream)
    {
        JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
        return false;
    }
    memset(stream, 0, sizeof(struct _jw_stream));

    PUSH_SOCKET_NDC;
    jw_log(JW_LOG_TRACE, "creating new socket stream");

    // Build up function table
    stream->func_table.jw_stream_destroy = _jw_stream_socket_destroy;
    stream->func_table.jw_stream_open    = _jw_stream_socket_open;
    stream->func_table.jw_stream_reopen  = _jw_stream_socket_reopen;
    stream->func_table.jw_stream_send    = _jw_stream_socket_send;
    stream->func_table.jw_stream_close   = _jw_stream_socket_close;

    stream->func_table.read_cb    = _read_stream_cb;
    stream->func_table.write_cb   = _write_stream_cb;
    stream->func_table.connect_cb = _connect_stream_cb;

    if (!_jw_stream_common_setup(stream, workq, err))
    {
        jw_stream_destroy(stream);
        POP_SOCKET_NDC;
        return false;
    }
    
    *retstream = stream;
    POP_SOCKET_NDC;
    return true;
}
