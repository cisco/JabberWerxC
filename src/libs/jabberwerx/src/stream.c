/**
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

#include <jabberwerx/stream.h>
#include <jabberwerx/util/htable.h>
#include <jabberwerx/util/log.h>
#include <jabberwerx/util/workq.h>

#include <event2/event.h>

#include "include/stream_int.h"
#include "include/dom_int.h"
#include "include/utils.h"

#include <assert.h>
#include <string.h>
#include <stdbool.h>


#define DEFAULT_KEEPALIVE_SECS 300 // 5 mins


static const char* STREAM_EVENTS[] = {
    JW_STREAM_EVENT_OPENED,
    JW_STREAM_EVENT_CLOSED,
    JW_STREAM_EVENT_ELEMRECV,
    JW_STREAM_EVENT_ELEMSENT,
    JW_STREAM_EVENT_DESTROYED,
    NULL
};


bool _jw_stream_common_setup(jw_stream *stream, jw_workq *workq, jw_err *err)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(stream);

    jw_event *event;

    if (!jw_event_dispatcher_create(stream, workq, &stream->dispatch, err))
    {
        return false;
    }

    if (!jw_event_prepare_trigger(
            stream->dispatch, &stream->destroy_trigger_data, err))
    {
        jw_event_dispatcher_destroy(stream->dispatch);
        stream->dispatch = NULL;
        return false;
    }

    stream->resource_error_dom =
            _jw_stream_create_error_node(JW_ERR_NO_MEMORY, NULL);
    if (!stream->resource_error_dom)
    {
        JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
        return false;
    }

    for (int index = 0; NULL != STREAM_EVENTS[index]; ++index)
    {
        if (!jw_event_dispatcher_create_event(
                stream->dispatch, STREAM_EVENTS[index], &event, err))
        {
            return false;
        }
    }

    return true;
}

/**
 * sets stream->error_dom if it is not already set.  uses the pre-allocated
 * resource_error_dom if the code is NO_MEMORY.  uses NULL if there is an error
 * while creating the node.  will include app_element in the generated node
 * if it is non-NULL.
 */
void _jw_stream_set_error_node_if_not_set(jw_stream   *stream,
                                          jw_errcode        errcode,
                                          jw_dom_node *app_element)
{
    JW_LOG_TRACE_FUNCTION("errcode=%d; appElement: %s",
                          errcode, app_element ? "defined" : "undefined");

    assert(stream);

    if (NULL != stream->error_dom)
    {
        jw_log_dom(JW_LOG_DEBUG, stream->error_dom,
                   "not overwriting error dom with %s; already set to: ",
                   jw_err_message(errcode));
        return;
    }

    if (errcode == JW_ERR_NO_MEMORY)
    {
        stream->error_dom = stream->resource_error_dom;
    }
    else
    {
        stream->error_dom =
                _jw_stream_create_error_node(errcode, app_element);
    }

    jw_log_dom(JW_LOG_DEBUG, stream->error_dom, "error dom now set to: ");
}

void _jw_stream_clean_error_dom(jw_stream *stream)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(stream);

    if (NULL == stream->error_dom)
    {
        return;
    }

    if (stream->resource_error_dom != stream->error_dom)
    {
        jw_dom_context_destroy(jw_dom_get_context(stream->error_dom));
    }
    
    stream->error_dom = NULL;
}

/*
 * Create a stream error element of the appropriate kind, where
 * the kind is intuited from a JWC error code.
 */
jw_dom_node *_jw_stream_create_error_node(jw_errcode errcode,
                                               jw_dom_node *app_element)
{
    JW_LOG_TRACE_FUNCTION("errcode=%d; appElement: %s",
                          errcode, app_element ? "defined" : "undefined");

    jw_dom_ctx  *errorCtx;
    jw_dom_node *errorNode;
    jw_dom_node *errorTypeNode;
    jw_err err;

    if (errcode == JW_ERR_NONE)
    {
        return NULL;
    }

    if (!jw_dom_context_create(&errorCtx, &err))
    {
        jw_log_err(JW_LOG_WARN, &err, "unable to construct error dom");
        return NULL;
    }

    if (!jw_dom_element_create_int(errorCtx,   JW_STREAM_ENAME_ERROR,
                                   &errorNode, &err))
    {
        jw_log_err(JW_LOG_WARN, &err, "unable to construct error dom");
        goto _create_stream_error_node_fail_label;
    }

    const char *errEname = NULL;
    switch (errcode)
    {
    case JW_ERR_NO_MEMORY:
        errEname = JW_STREAM_ERROR_NO_RSRC;
        break;

    case JW_ERR_INVALID_ARG:
    case JW_ERR_INVALID_STATE:
    case JW_ERR_PROTOCOL:
        errEname = JW_STREAM_ERROR_INT_SERVER;
        break;

    case JW_ERR_SOCKET_CONNECT:
        errEname = JW_STREAM_ERROR_SOCK_CONNECT;
        break;

    case JW_ERR_NOT_AUTHORIZED:
        errEname = JW_STREAM_ERROR_NOT_AUTHORIZED;
        break;

    default:
        if (NULL == app_element)
        {
            // Note: NOT jw_log_err on purpose
            jw_log(JW_LOG_WARN, "unhandled error code: %d (%s)",
                   errcode, jw_err_message(errcode));
            goto _create_stream_error_node_fail_label;
        }
        
        errEname = JW_STREAM_ERROR_UNDEFINED_CONDITION;
    }

    if (!jw_dom_element_create_int(errorCtx, errEname, &errorTypeNode, &err))
    {
        jw_log_err(JW_LOG_WARN, &err, "unable to construct error dom");
        goto _create_stream_error_node_fail_label;
    }

    if (!jw_dom_add_child(errorNode, errorTypeNode, &err))
    {
        jw_log_err(JW_LOG_WARN, &err, "unable to construct error dom");
        goto _create_stream_error_node_fail_label;
    }

    if (NULL != app_element)
    {
        jw_dom_node *appElem;
        if (!jw_dom_import(errorCtx, app_element, true, &appElem, &err))
        {
            jw_log_err(JW_LOG_WARN, &err,
                     "unable to import app condition element for error dom");
            goto _create_stream_error_node_fail_label;
        }

        if (!jw_dom_add_child(errorNode, appElem, &err))
        {
            jw_log_err(JW_LOG_WARN, &err, "unable to construct error dom");
            goto _create_stream_error_node_fail_label;
        }
    }

    return errorNode;

_create_stream_error_node_fail_label:
    jw_dom_context_destroy(errorCtx);
    return NULL;
}

bool _prepare_for_disconnect(jw_stream *stream,
                             jw_workq_func onCloseCb, jw_err *err)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(stream);
    assert(!stream->close_event);
    assert(!stream->close_trigger_data);
    
    // prepare for orderly shutdown
    jw_workq *workq = jw_event_dispatcher_get_workq(stream->dispatch);
    if (!jw_workq_item_create(workq, onCloseCb, &stream->close_event, err))
    {
        jw_log_err(JW_LOG_WARN, err,
                   "failed to create workq item for stream close event");
        return false;
    }
    jw_workq_item_set_data(stream->close_event, stream, NULL);
    
    if (!jw_event_prepare_trigger(
            stream->dispatch, &stream->close_trigger_data, err))
    {
        return false;
    }
    
    return true;
}

void _clean_disconnect_data(jw_stream *stream)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(stream);

    if (stream->close_event)
    {
        jw_workq_item_destroy(stream->close_event);
        stream->close_event = NULL;
    }
    
    if (stream->close_trigger_data)
    {
        jw_event_unprepare_trigger(stream->close_trigger_data);
        stream->close_trigger_data = NULL;
    }
}

void _reset_state_result_cb(jw_event_data evt, bool result, void *arg)
{
    UNUSED_PARAM(result);
    UNUSED_PARAM(arg);

    jw_stream *stream = evt->source;
    assert(stream);

    stream->state = STATE_STREAM_INIT;

    JW_LOG_TRACE_FUNCTION("stream=%p", (void *)stream);

    if (stream->destroy_pending)
    {
        stream->destroy_pending = false;
        jw_stream_destroy(stream);
    }
}

uint32_t _get_keepalive_ms(jw_stream *stream)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(stream);
    
    double dtime;
    jw_err err;

    if (!jw_utils_config_get_double(
            stream->config,
            JW_STREAM_CONFIG_KEEPALIVE_SECONDS,
            DEFAULT_KEEPALIVE_SECS,
            &dtime, &err))
    {
        jw_log_err(JW_LOG_WARN, &err,
                   "Could not parse JW_STREAM_CONFIG_KEEPALIVE_SECONDS value");
        dtime = DEFAULT_KEEPALIVE_SECS;
    }
    
    return jw_utils_dtoms(dtime);
}

const char * _jw_stream_state_to_str(jw_stream *stream)
{
    const char *ret = "?";
    if (stream)
    {
        switch (stream->state)
        {
        case STATE_STREAM_INIT:        ret = "STATE_STREAM_INIT";        break;
        case STATE_SOCKET_RESOLVE:     ret = "STATE_SOCKET_RESOLVE";     break;
        case STATE_SOCKET_CONNECT:     ret = "STATE_SOCKET_CONNECT";     break;
        case STATE_SOCKET_STREAM_OUT:  ret = "STATE_SOCKET_STREAM_OUT";  break;
        case STATE_SOCKET_STREAM_IN:   ret = "STATE_SOCKET_STREAM_IN";   break;
        case STATE_SOCKET_FEATURES_IN: ret = "STATE_SOCKET_FEATURES_IN"; break;
        case STATE_STREAM_READY:       ret = "STATE_STREAM_READY";       break;
        case STATE_STREAM_CLOSING:     ret = "STATE_STREAM_CLOSING";     break;
        default:
            break;
        }
    }
    return ret;
}

struct _log_evbuffer_data
{
    struct evbuffer    *buf;
    struct evbuffer_ptr ptr;
};

static void _log_evbuffer_generator(
         const char **chunk, size_t *len, jw_data_free_func *free_fn, void *arg)
{
    UNUSED_PARAM(free_fn);

    assert(chunk);
    assert(len);
    assert(free_fn);

    struct _log_evbuffer_data *chunk_info = arg;

    struct evbuffer_iovec v[1];
    if (!chunk_info || !chunk_info->buf
     || 1 > evbuffer_peek(chunk_info->buf, -1, &chunk_info->ptr, v, 1))
    {
        // out of data
        return;
    }

    *chunk = v[0].iov_base;
    *len   = v[0].iov_len;

    // advance the pointer so we see the next chunk next time
    if (0 != evbuffer_ptr_set(chunk_info->buf, &chunk_info->ptr,
                              *len, EVBUFFER_PTR_ADD))
    {
        // this was the last chunk and the next use of ptr will fail
        chunk_info->buf = NULL;
    }
}

void _log_evbuffer(jw_loglevel level,
                   struct evbuffer *buffer, const char *preamble)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    // do nothing if logging is not required
    if (!buffer || level > jw_log_get_level())
    {
        return;
    }

    size_t bufflen = evbuffer_get_length(buffer);
    if (0 >= bufflen)
    {
        jw_log(level, "%s empty body", preamble);
        return;
    }

    struct _log_evbuffer_data data;
    data.buf = buffer;

    // initialize ptr
    if (0 > evbuffer_ptr_set(buffer, &data.ptr, 0, EVBUFFER_PTR_SET))
    {
        jw_log(JW_LOG_WARN, "%s: [failed to output body]", preamble);
        return;
    }

    jw_log_chunked(level, _log_evbuffer_generator, &data, "%s: ", preamble);
}


/********************************************
 * Public API functions
 *******************************************/
JABBERWERX_API void jw_stream_destroy(jw_stream *stream)
{
    JW_LOG_TRACE_FUNCTION("stream=%p", (void *)stream);

    assert(stream);

    if (STATE_STREAM_CLOSING == stream->state)
    {
        jw_log(JW_LOG_DEBUG, "enqueueing stream destruction");
        stream->destroy_pending = true;
        return;
    }

    if (STATE_STREAM_INIT != stream->state)
    {
        jw_log(JW_LOG_WARN,
               "destroying stream without closing first; leaks are likely");
    }

   (stream->func_table).jw_stream_destroy(stream);
}

JABBERWERX_API bool jw_stream_open(jw_stream *stream,
                                   jw_htable *config,
                                   jw_err *err)
{
    JW_LOG_TRACE_FUNCTION("stream=%p", (void *)stream);

    assert(stream);
    
    // check for common required config elements
    if (!jw_htable_get(config, JW_STREAM_CONFIG_NAMESPACE))
    {
        JABBERWERX_ERROR(err, JW_ERR_INVALID_ARG);
        return false;
    }
    
    if (!jw_htable_get(config, JW_STREAM_CONFIG_DOMAIN))
    {
        JABBERWERX_ERROR(err, JW_ERR_INVALID_ARG);
        return false;
    }

    jw_workq *workq = jw_event_dispatcher_get_workq(stream->dispatch);
    if (!jw_htable_put(config, JW_STREAM_CONFIG_SELECTOR,
                        jw_workq_get_selector(workq), NULL, err))
    {
        jw_log_err(JW_LOG_WARN, err,
                    "could not add selector to stream config htable");
        return false;
    }

    return (stream->func_table).jw_stream_open(stream, config, err);
}

JABBERWERX_API bool jw_stream_reopen(jw_stream *stream,
                                     jw_err *err)
{
    JW_LOG_TRACE_FUNCTION("stream=%p", (void *)stream);

    assert(stream);
    return (stream->func_table).jw_stream_reopen(stream, err);
}

JABBERWERX_API bool jw_stream_send(jw_stream *stream,
                                   jw_dom_node *dom,
                                   jw_err *err)
{
    JW_LOG_TRACE_FUNCTION("stream=%p", (void *)stream);

    assert(stream);
    return (stream->func_table).jw_stream_send(stream, dom, err);
}

JABBERWERX_API void jw_stream_close(jw_stream *stream,
                                    jw_errcode close_reason)
{
    JW_LOG_TRACE_FUNCTION("stream=%p", (void *)stream);

    assert(stream);
    if (NULL == stream->close_trigger_data)
    {
        jw_log(JW_LOG_DEBUG,
               "stream closure already in progress; ignoring close request");
    }
    else
    {
        (stream->func_table).jw_stream_close(stream, close_reason);
    }
}

JABBERWERX_API const char* jw_stream_get_stream_id(jw_stream *stream)
{
    JW_LOG_TRACE_FUNCTION("stream=%p", (void *)stream);

    assert(stream);
    if (!stream->config)
    {
        return NULL;
    }

    return jw_htable_get(stream->config,
                         (const void*)JW_STREAM_CONFIG_STREAM_ID_);
}

JABBERWERX_API const char* jw_stream_get_namespace(jw_stream *stream)
{
    JW_LOG_TRACE_FUNCTION("stream=%p", (void *)stream);

    assert(stream);
    if (!stream->config)
    {
        return NULL;
    }

    return jw_htable_get(stream->config,
                         (const void*)JW_STREAM_CONFIG_NAMESPACE);
}

JABBERWERX_API const char* jw_stream_get_domain(jw_stream *stream)
{
    JW_LOG_TRACE_FUNCTION("stream=%p", (void *)stream);

    assert(stream);
    if (!stream->config)
    {
        return NULL;
    }

    return jw_htable_get(stream->config,
                         (const void*)JW_STREAM_CONFIG_DOMAIN);
}

JABBERWERX_API struct event_base* jw_stream_get_selector(jw_stream *stream)
{
    JW_LOG_TRACE_FUNCTION("stream=%p", (void *)stream);

    assert(stream);
    return stream->base;
}

JABBERWERX_API jw_workq* jw_stream_get_workq(jw_stream *stream)
{
    JW_LOG_TRACE_FUNCTION("stream=%p", (void *)stream);

    assert(stream);
    assert(stream->dispatch);
    return jw_event_dispatcher_get_workq(stream->dispatch);
}

JABBERWERX_API jw_htable *jw_stream_get_config(jw_stream *stream)
{
    JW_LOG_TRACE_FUNCTION("stream=%p", (void *)stream);

    assert(stream);
    return stream->config;
}

JABBERWERX_API bool jw_stream_is_open(jw_stream *stream)
{
    JW_LOG_TRACE_FUNCTION("stream=%p", (void *)stream);
    assert(stream);
    return stream->state == STATE_STREAM_READY;
}

JABBERWERX_API jw_event *jw_stream_event(jw_stream *stream, const char *name)
{
    JW_LOG_TRACE_FUNCTION("stream=%p", (void *)stream);

    assert(stream);
    assert(name != NULL && *name != '\0');

    return jw_event_dispatcher_get_event(stream->dispatch, name);
}

JABBERWERX_API struct bufferevent *jw_stream_get_bufferevent(jw_stream *stream)
{
    JW_LOG_TRACE_FUNCTION("stream=%p", (void *)stream);

    assert(stream);
    return stream->bevent;
}

JABBERWERX_API bool jw_stream_set_bufferevent(jw_stream *stream,
                                              struct bufferevent *bev,
                                              jw_err *err)
{
    JW_LOG_TRACE_FUNCTION("stream=%p; bev=%p", (void *)stream, (void *)bev);

    assert(stream);
    if (stream->bevent == NULL)
    {
        JABBERWERX_ERROR(err, JW_ERR_INVALID_STATE);
        return false;
    }

    if (bev != NULL)
    {
        bufferevent_setcb(bev,
                          (stream->func_table).read_cb,
                          (stream->func_table).write_cb,
                          (stream->func_table).connect_cb,
                          stream);

        stream->bevent = bev;
        return true;
    }
    else
    {
        JABBERWERX_ERROR(err, JW_ERR_INVALID_ARG);
        return false;
    }
}

JABBERWERX_API struct bufferevent *
jw_stream_add_filter(jw_stream *stream,
                     bufferevent_filter_cb input,
                     bufferevent_filter_cb output,
                     int options,
                     jw_data_free_func free_filter_ctx,
                     void *ctx,
                     jw_err *err)
{
    JW_LOG_TRACE_FUNCTION("stream=%p", (void *)stream);

    assert(stream);
    if (input == NULL || output == NULL)
    {
        JABBERWERX_ERROR(err, JW_ERR_INVALID_ARG);
        return NULL;
    }
    if (stream->bevent == NULL)
    {
        JABBERWERX_ERROR(err, JW_ERR_INVALID_STATE);
        return NULL;
    }

    struct bufferevent *filter = bufferevent_filter_new(stream->bevent,
                                                        input,
                                                        output,
                                                        options,
                                                        free_filter_ctx,
                                                        ctx);
    if (filter == NULL)
    {
        JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
        return NULL;
    }
    bufferevent_setcb(filter,
                      (stream->func_table).read_cb,
                      (stream->func_table).write_cb,
                      (stream->func_table).connect_cb,
                      (void*)stream);

    if (bufferevent_enable(filter, EV_READ|EV_WRITE) != 0)
    {
        /* TODO discuss appropriate xmpp error to send, currently using
         * JW_ERR_INVALID_ARG which in turn send internal-server-error
         */
        JABBERWERX_ERROR(err, JW_ERR_INVALID_ARG);
        return NULL;
    }

    stream->bevent = filter;

    return filter;
}
