/**
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

#include <assert.h>
#include <expat.h>
#include <event2/event.h>
#include <unistd.h>
#include <string.h>
#include "stream_test.h"
#include "test_utils.h"
#include "stanza_defines.h"


void _test_stream_hooks_init(_test_create_stream_cb     create_stream_cb,
                             struct _test_stream_hooks *hooks)
{
    assert(hooks);
    memset(hooks, 0, sizeof(struct _test_stream_hooks));
    hooks->create_stream_cb = create_stream_cb;
}

static bool _loopbreak(jw_stream *stream)
{
    assert(stream);
    struct event_base *evbase = jw_stream_get_selector(stream);
    if (evbase)
    {
        if (0 != event_base_loopbreak(evbase))
        {
            jw_log(JW_LOG_ERROR, "failed to break out of event loop");
            return false;
        }
    }
    return true;
}

static void _on_stream_event(jw_event_data evt, void *arg)
{
    assert(evt);
    JW_LOG_TRACE_FUNCTION("evt: %s", evt->name);

    if (!evt->handled)
    {
        _loopbreak(evt->source);
        evt->handled = true;
    }

    assert(arg);
    *((bool *)arg) = true;
}

static void _on_received_presence2(jw_event_data evt, void *arg)
{
    assert(evt);
    JW_LOG_TRACE_FUNCTION("evt: %s", evt->name);

    bool *failed = arg;
    assert(failed);

    *failed = !_loopbreak(evt->source);
}

static void _on_received_presence1(jw_event_data evt, void *arg)
{
    assert(evt);
    JW_LOG_TRACE_FUNCTION("evt: %s", evt->name);

    jw_stream *stream = evt->source;
    assert(stream);
    bool *failed = arg;
    assert(failed);

    jw_dom_ctx  *ctx = NULL;
    jw_dom_node *presence;

    *failed = !jw_dom_context_create(&ctx, NULL)
          || !jw_dom_element_create(ctx, XMPP_CLIENT_PRESENCE, &presence, NULL);

    if (!*failed)
    {
        jw_event *received_event =
                jw_stream_event(stream, JW_STREAM_EVENT_ELEMRECV);
        jw_event_unbind(received_event, _on_received_presence1);

        *failed = !jw_stream_send(stream, presence, NULL)
               || !jw_event_bind(received_event,
                                 _on_received_presence2, failed, NULL);
    }
    else if (ctx)
    {
        jw_dom_context_destroy(ctx);
    }

    if (*failed)
    {
        _loopbreak(stream);
    }
}

static void _on_received_bind(jw_event_data evt, void *arg)
{
    assert(evt);
    JW_LOG_TRACE_FUNCTION("evt: %s", evt->name);

    jw_stream *stream = evt->source;
    assert(stream);
    bool *failed = arg;
    assert(failed);

    jw_dom_ctx  *ctx = NULL;
    jw_dom_node *presence;

    *failed = !jw_dom_context_create(&ctx, NULL)
          || !jw_dom_element_create(ctx, XMPP_CLIENT_PRESENCE, &presence, NULL);

    if (!*failed)
    {
        jw_event *received_event =
                jw_stream_event(stream, JW_STREAM_EVENT_ELEMRECV);
        jw_event_unbind(received_event, _on_received_bind);

        *failed = !jw_stream_send(stream, presence, NULL)
               || !jw_event_bind(received_event,
                                 _on_received_presence1, failed, NULL);
    }
    else if (ctx)
    {
        jw_dom_context_destroy(ctx);
    }

    if (*failed)
    {
        _loopbreak(stream);
    }
}

static void _on_opened_bind(jw_event_data evt, void *arg)
{
    assert(evt);
    JW_LOG_TRACE_FUNCTION("evt: %s", evt->name);

    jw_stream *stream = evt->source;
    assert(stream);
    bool *failed = arg;
    assert(failed);

    jw_dom_ctx  *ctx = NULL;
    jw_dom_node *iq, *bind;


    *failed = !jw_dom_context_create(&ctx, NULL)
           || !jw_dom_element_create(ctx, XMPP_CLIENT_IQ, &iq, NULL)
           || !jw_dom_set_attribute(iq, "{}id", "random", NULL)
           || !jw_dom_set_attribute(iq, "{}type", "set", NULL)
           || !jw_dom_element_create(ctx, XMPP_BIND, &bind, NULL)
           || !jw_dom_add_child(iq, bind, NULL);

    if (!*failed)
    {
        *failed = !jw_stream_send(stream, iq, NULL)
               || !jw_event_bind(
                        jw_stream_event(stream, JW_STREAM_EVENT_ELEMRECV),
                        _on_received_bind, failed, NULL);
    }
    else if (ctx)
    {
        jw_dom_context_destroy(ctx);
    }

    if (*failed)
    {
        _loopbreak(stream);
    }
}

static void _on_opened_auth(jw_event_data evt, void *arg)
{
    assert(evt);
    JW_LOG_TRACE_FUNCTION("evt: %s", evt->name);

    jw_stream *stream = evt->source;
    assert(stream);
    bool *failed = arg;
    assert(failed);

    jw_dom_ctx  *ctx = NULL;
    jw_dom_node *auth, *auth_text;

    *failed = !jw_dom_context_create(&ctx, NULL)
           || !jw_dom_element_create(ctx, XMPP_SASL_AUTH, &auth, NULL)
           || !jw_dom_set_attribute(auth, "{}mechanism", "PLAIN", NULL)
           || !jw_dom_text_create(ctx, "=", &auth_text, NULL)
           || !jw_dom_add_child(auth, auth_text, NULL);

    if (!*failed)
    {
        jw_event *opened_event =
                jw_stream_event(stream, JW_STREAM_EVENT_OPENED);
        jw_event_unbind(opened_event, _on_opened_auth);

        *failed = !jw_stream_send(stream, auth, NULL)
               || !jw_event_bind(opened_event,
                                 _on_opened_bind, failed, NULL);
    }
    else if (ctx)
    {
        jw_dom_context_destroy(ctx);
    }

    if (*failed)
    {
        _loopbreak(stream);
    }
}

static void _on_elemrecv_auth(jw_event_data evt, void *arg)
{
    assert(evt);
    JW_LOG_TRACE_FUNCTION("evt: %s", evt->name);

    jw_stream *stream = evt->source;
    assert(stream);
    bool *failed = arg;
    assert(failed);

    jw_event *elemrecv_event =
            jw_stream_event(stream, JW_STREAM_EVENT_ELEMRECV);
    jw_event_unbind(elemrecv_event, _on_elemrecv_auth);

    *failed = !jw_stream_reopen(stream, NULL);

    if (*failed)
    {
        _loopbreak(stream);
    }
}

bool _test_stream_basic(struct _test_stream_hooks *hooks,
                        jw_err                    *err)
{
    assert(hooks);
    assert(hooks->create_stream_cb);

    struct event_base *evbase        = NULL;
    struct event      *failsafeEvent = NULL;
    jw_htable         *config        = NULL;
    jw_workq          *workq         = NULL;
    jw_stream         *stream        = NULL;

    bool ret = false;

    if (err)
    {
        err->code = JW_ERR_NONE;
    }

    jw_log(JW_LOG_INFO, "initializing stream test");
    if (!_test_init(&evbase, &failsafeEvent, &config, &workq, NULL)
     || !hooks->create_stream_cb(workq, &stream, err))
    {
        goto _test_basic_stream_done_label;
    }

    bool closed    = false;
    bool destroyed = false;
    bool failed    = false;
    
    if (hooks->before_bind_cb)
    {
        jw_log(JW_LOG_INFO, "running before bind callback");
        if (!hooks->before_bind_cb(stream, config,
                                   hooks->before_bind_cb_arg, &failed))
        {
            jw_log(JW_LOG_INFO, "failed during before bind callback");
            goto _test_basic_stream_done_label;
        }
    }

    if (!jw_event_bind(jw_stream_event(stream, JW_STREAM_EVENT_OPENED),
                       _on_opened_auth, &failed, err)
     || !jw_event_bind(jw_stream_event(stream, JW_STREAM_EVENT_ELEMRECV),
                       _on_elemrecv_auth, &failed, err)
     || !jw_event_bind(jw_stream_event(stream, JW_STREAM_EVENT_CLOSED),
                       _on_stream_event, &closed, err)
     || !jw_event_bind(jw_stream_event(stream, JW_STREAM_EVENT_DESTROYED),
                       _on_stream_event, &destroyed, err))
    {
        goto _test_basic_stream_done_label;
    }

    jw_log(JW_LOG_INFO, "opening stream");
    if (!jw_stream_open(stream, config, err)
     || -1 == event_base_dispatch(evbase)
     || closed || failed || !jw_stream_is_open(stream) || _test_get_timed_out())
    {
        jw_log(JW_LOG_INFO, "failed after open");
        goto _test_basic_stream_done_label;
    }

    if (hooks->after_presence_cb)
    {
        jw_log(JW_LOG_INFO, "running after presence callback");
        if (!hooks->after_presence_cb(stream, hooks->after_presence_cb_arg,
                                      &failed)
         || -1 == event_base_dispatch(evbase)
         || closed || failed || !jw_stream_is_open(stream)
         || _test_get_timed_out())
        {
            jw_log(JW_LOG_INFO, "failed during after presence callback");
            goto _test_basic_stream_done_label;
        }
    }

    jw_log(JW_LOG_INFO, "closing stream");
    jw_stream_close(stream, err ? err->code : JW_ERR_NONE);
    if (-1 == event_base_dispatch(evbase)
     || !closed || failed || destroyed || _test_get_timed_out())
    {
        jw_log(JW_LOG_INFO, "failed after close");
        if (destroyed)
        {
            stream = NULL;
        }
        goto _test_basic_stream_done_label;
    }

    jw_log(JW_LOG_INFO, "destroying stream");
    jw_stream_destroy(stream);
    stream = NULL;
    if (-1 == event_base_dispatch(evbase)
     || !destroyed || _test_get_timed_out())
    {
        jw_log(JW_LOG_ERROR, "failed to destroy stream");
        goto _test_basic_stream_done_label;
    }

    ret = true;

_test_basic_stream_done_label:
    jw_log(JW_LOG_INFO, "cleaning up test");
    if (stream)
    {
        if (jw_stream_is_open(stream))
        {
            jw_stream_close(stream, err ? err->code : JW_ERR_NONE);
            event_base_dispatch(evbase);
        }

        jw_stream_destroy(stream);
        event_base_loop(evbase, EVLOOP_NONBLOCK);
    }

    if (hooks->before_cleanup_cb)
    {
        jw_log(JW_LOG_INFO, "running before cleanup callback");
        hooks->before_cleanup_cb(hooks->before_cleanup_cb_arg);
    }

    // allow any leftover events to flush (necessary for bufferevent refcounts
    // to reach 0 in some tests)
    event_base_loop(evbase, EVLOOP_NONBLOCK);

    _test_cleanup(evbase, failsafeEvent, config, workq, NULL);
    return ret && !_test_get_timed_out();
}

static bool _clear_config_before_bind(
                jw_stream *stream, jw_htable *config, void *arg, bool *failed)
{
    UNUSED_PARAM(failed);
    
    bool *failed_with_invalid_arg = arg;

    bool closed = false;
    jw_event *closed_evt = jw_stream_event(stream, JW_STREAM_EVENT_CLOSED);
    if (!jw_event_bind(closed_evt, _on_stream_event, &closed, NULL))
    {
        goto _clear_config_before_bind_done_label;
    }

    struct event_base *evbase =
                jw_htable_get(config, JW_STREAM_CONFIG_SELECTOR);
    if (!evbase)
    {
        goto _clear_config_before_bind_done_label;
    }

    // remove required configuration
    jw_htable_clear(config);

    jw_err err;
    if (jw_stream_open(stream, config, &err)
     || -1 == event_base_loop(evbase, EVLOOP_NONBLOCK)
     || closed)
    {
        goto _clear_config_before_bind_done_label;
    }
    
    *failed_with_invalid_arg = (err.code == JW_ERR_INVALID_ARG);

_clear_config_before_bind_done_label:
    jw_event_unbind(closed_evt, _on_stream_event);
    return false; // stop the test after this point
}

bool _test_stream_no_config(struct _test_stream_hooks *hooks,
                            jw_err                    *err)
{
    bool failed_with_invalid_arg = false;
    struct _test_stream_hooks realhooks = *hooks;
    realhooks.before_bind_cb     = _clear_config_before_bind;
    realhooks.before_bind_cb_arg = &failed_with_invalid_arg;

    return !_test_stream_basic(&realhooks, err) && failed_with_invalid_arg;
}


static void _on_close_do_destroy(jw_event_data evt, void *arg)
{
    UNUSED_PARAM(arg);
    assert(evt);
    JW_LOG_TRACE_FUNCTION("evt: %s", evt->name);

    jw_stream *stream = evt->source;
    assert(stream);
    jw_stream_destroy(stream);
    evt->handled = true;
}

struct _before_bind_cb
{
    _test_before_bind_cb before_bind_cb;
    void                *before_bind_cb_arg;
};

static bool _close_destroy_before_bind(
            jw_stream *stream, jw_htable *config, void *arg, bool *failed)
{
    struct _before_bind_cb *cbdata = arg;

    jw_event *closed_evt = jw_stream_event(stream, JW_STREAM_EVENT_CLOSED);
    return jw_event_bind(closed_evt, _on_close_do_destroy, failed, NULL)
     && (!cbdata
         || !cbdata->before_bind_cb
         || cbdata->before_bind_cb(stream, config,
                                   cbdata->before_bind_cb_arg, failed));
}

static bool _test_stream_chained_before_bind(struct _test_stream_hooks *hooks,
                                             _test_before_bind_cb       bbindfn,
                                             jw_err                    *err)
{
    assert(hooks);
    struct _before_bind_cb cbdata = {
        .before_bind_cb     = hooks->before_bind_cb,
        .before_bind_cb_arg = hooks->before_bind_cb_arg };
    struct _test_stream_hooks realhooks = *hooks;
    realhooks.before_bind_cb     = bbindfn;
    realhooks.before_bind_cb_arg = &cbdata;
    return _test_stream_basic(&realhooks, err);
}

bool _test_stream_destroy_from_close(struct _test_stream_hooks *hooks,
                                     jw_err                    *err)
{
    return
      !_test_stream_chained_before_bind(hooks, _close_destroy_before_bind, err);
}


static void _on_opened_do_sleep(jw_event_data evt, void *arg)
{
    UNUSED_PARAM(arg);
    assert(evt);
    JW_LOG_TRACE_FUNCTION("evt: %s", evt->name);

    // sleep for at least one millisecond
    while (0 != usleep(1000));
}

static bool _modify_keepalive_before_bind(
            jw_stream *stream, jw_htable *config, void *arg, bool *failed)
{
    struct _before_bind_cb *cbdata = arg;

    jw_event *opened_evt = jw_stream_event(stream, JW_STREAM_EVENT_OPENED);
    return jw_htable_put(
                config, JW_STREAM_CONFIG_KEEPALIVE_SECONDS, "0.001", NULL, NULL)
        && jw_event_bind(opened_evt, _on_opened_do_sleep, failed, NULL)
        && (!cbdata
         || !cbdata->before_bind_cb
         || cbdata->before_bind_cb(stream, config,
                                   cbdata->before_bind_cb_arg, failed));
}

bool _test_stream_keepalive(struct _test_stream_hooks *hooks,
                            jw_err                    *err)
{
    return _test_stream_chained_before_bind(hooks,
                                            _modify_keepalive_before_bind, err);
}


struct _after_presence_cb
{
    _test_after_presence_cb after_presence_cb;
    void                   *after_presence_cb_arg;
};

static bool _after_presence_send_error(
                jw_stream *stream, void *arg, bool *failed)
{
    struct _after_presence_cb *cbdata = arg;

    jw_dom_ctx  *ctx = NULL;
    jw_dom_node *presence, *errnode, *errtext;

    *failed = !jw_dom_context_create(&ctx, NULL)
           || !jw_dom_element_create(ctx, XMPP_CLIENT_PRESENCE, &presence, NULL)
           || !jw_dom_element_create(ctx, XMPP_CLIENT_ERROR, &errnode, NULL)
           || !jw_dom_text_create(ctx, "error text", &errtext, NULL)
           || !jw_dom_add_child(errnode, errtext, NULL)
           || !_jw_test_echosrv_core_add_command(presence, JW_ECHOSRV_CMD_SEND,
                                                 errnode, NULL)
           || !jw_stream_send(stream, presence, NULL);

    if (*failed)
    {
        if (ctx)
        {
            jw_dom_context_destroy(ctx);
        }

        _loopbreak(stream);
    }

    return !*failed
        || (cbdata->after_presence_cb
            && cbdata->after_presence_cb(stream, cbdata->after_presence_cb_arg,
                                         failed));
}

bool _test_stream_error_elem(struct _test_stream_hooks *hooks,
                             jw_err                    *err)
{
    struct _after_presence_cb cbdata = {
        .after_presence_cb     = hooks->after_presence_cb,
        .after_presence_cb_arg = hooks->after_presence_cb_arg };
    struct _test_stream_hooks realhooks = *hooks;
    realhooks.after_presence_cb     = _after_presence_send_error;
    realhooks.after_presence_cb_arg = &cbdata;
    return !_test_stream_basic(&realhooks, err);
}


void _test_remove_expat_malloc_monitoring()
{
    // override expat allocators until the leak in expat is sussed out
    // (see parser.c:50)
    extern XML_Memory_Handling_Suite _xmlMs;
    _xmlMs.malloc_fcn  = malloc;
    _xmlMs.realloc_fcn = realloc;
    _xmlMs.free_fcn    = free;
}

void _test_restore_expat_malloc_monitoring()
{
    extern XML_Memory_Handling_Suite _xmlMs;
    _xmlMs.malloc_fcn  = jw_data_malloc;
    _xmlMs.realloc_fcn = jw_data_realloc;
    _xmlMs.free_fcn    = jw_data_free;
}
