/**
 * \file
 * JabberWerxC Simple Stream
 *
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2011 Cisco Systems, Inc.  All Rights Reserved.
 */

/**
 * Note this program does not handle memory allocation errors as it must not
 * ever be used as anything but a demo.
 */

#include "sasl_plain.h"
#include "bind.h"
#include "simplestream_defines.h"
#include "simplestream_utils.h"
#include "option_parser.h"

#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <arpa/inet.h>

#include <jabberwerx/jabberwerx.h>

#include <event2/event.h>
#include <event2/bufferevent.h>


static void onConnected(jw_event_data event, void *data)
{
    jw_stream *stream = event->source;
    jw_dom_node *streamNode = event->data;
    jw_htable *config = data;

    printf("stream connected\n");
    printElement(streamNode);

    if (doSaslPlain(stream, streamNode, config))
    {
        return;
    }
    
    if (doBind(stream, streamNode))
    {
        return;
    }

    jw_log(JW_LOG_ERROR, "can't authenticate or bind");
    jw_stream_close(stream, JW_ERR_NOT_AUTHORIZED);
}

static void onDisconnected(jw_event_data event, void *data)
{
    UNUSED_PARAM(event);
    UNUSED_PARAM(data);

    printf("stream disconnected\n");
}

static void onDestroyed(jw_event_data event, void *data)
{
    UNUSED_PARAM(event);
    UNUSED_PARAM(data);

    printf("stream object destroyed\n");
}

static void onElementsReceived(jw_event_data event, void *arg)
{
    UNUSED_PARAM(arg);

    printf("elements received\n");
    printElements(event->data);
}

static void onElementsSent(jw_event_data event, void *data)
{
    UNUSED_PARAM(data);

    printf("elements sent\n");
    printElements(event->data);
}

static void closeStreamCallback(evutil_socket_t sock, short what, void *arg)
{
    UNUSED_PARAM(sock);
    UNUSED_PARAM(what);

    jw_stream *stream = arg;

    printf("closing the stream\n");
    jw_stream_close(stream, JW_ERR_NONE);
}

enum bufferevent_filter_result log_input(struct evbuffer *src,
                                         struct evbuffer *dst,
                                         ev_ssize_t dst_limit,
                                         enum bufferevent_flush_mode mode,
                                         void *ctx)
{
    UNUSED_PARAM(dst_limit);
    UNUSED_PARAM(mode);
    UNUSED_PARAM(ctx);

    size_t bufflen;
    size_t buffpos = 0;
    struct evbuffer_iovec v;

    bufflen = (src ? evbuffer_get_length(src) : 0);

    while (buffpos < bufflen)
    {
        struct evbuffer_ptr ptr;
        evbuffer_ptr_set(src, &ptr, buffpos, EVBUFFER_PTR_SET);

        evbuffer_peek(src, -1, &ptr, &v, 1);
        jw_log(JW_LOG_DEBUG, "input filter: %*s",
               (int)v.iov_len, (char *)v.iov_base);

        buffpos += v.iov_len;
    }

    evbuffer_add_buffer(dst, src);
    return BEV_OK;
}

enum bufferevent_filter_result log_output(struct evbuffer *src,
                                          struct evbuffer *dst,
                                          ev_ssize_t dst_limit,
                                          enum bufferevent_flush_mode mode,
                                          void *ctx)
{
    UNUSED_PARAM(dst_limit);
    UNUSED_PARAM(mode);
    UNUSED_PARAM(ctx);

    size_t bufflen;
    size_t buffpos = 0;
    struct evbuffer_iovec v;

    bufflen = (src ? evbuffer_get_length(src) : 0);

    while (buffpos < bufflen)
    {
        struct evbuffer_ptr ptr;
        evbuffer_ptr_set(src, &ptr, buffpos, EVBUFFER_PTR_SET);

        evbuffer_peek(src, -1, &ptr, &v, 1);
        jw_log(JW_LOG_DEBUG, "output filter: %*s",
               (int)v.iov_len, (char *)v.iov_base);

        buffpos += v.iov_len;
    }

    evbuffer_add_buffer(dst, src);
    return BEV_OK;
}

enum bufferevent_filter_result log2_input(struct evbuffer *src,
                                          struct evbuffer *dst,
                                          ev_ssize_t dst_limit,
                                          enum bufferevent_flush_mode mode,
                                          void *ctx)
{
    UNUSED_PARAM(dst_limit);
    UNUSED_PARAM(mode);
    UNUSED_PARAM(ctx);

    size_t bufflen;
    size_t buffpos = 0;
    struct evbuffer_iovec v;

    bufflen = (src ? evbuffer_get_length(src) : 0);

    while (buffpos < bufflen)
    {
        struct evbuffer_ptr ptr;
        evbuffer_ptr_set(src, &ptr, buffpos, EVBUFFER_PTR_SET);

        evbuffer_peek(src, -1, &ptr, &v, 1);
        jw_log(JW_LOG_DEBUG, "input filter 2: %*s",
               (int)v.iov_len, (char *)v.iov_base);

        buffpos += v.iov_len;
    }

    evbuffer_add_buffer(dst, src);
    return BEV_OK;
}

enum bufferevent_filter_result log2_output(struct evbuffer *src,
                                           struct evbuffer *dst,
                                           ev_ssize_t dst_limit,
                                           enum bufferevent_flush_mode mode,
                                           void *ctx)
{
    UNUSED_PARAM(dst_limit);
    UNUSED_PARAM(mode);
    UNUSED_PARAM(ctx);

    size_t bufflen;
    size_t buffpos = 0;
    struct evbuffer_iovec v;

    bufflen = (src ? evbuffer_get_length(src) : 0);

    while (buffpos < bufflen)
    {
        struct evbuffer_ptr ptr;
        evbuffer_ptr_set(src, &ptr, buffpos, EVBUFFER_PTR_SET);

        evbuffer_peek(src, -1, &ptr, &v, 1);
        jw_log(JW_LOG_DEBUG, "output filter 2: %*s",
               (int)v.iov_len, (char *)v.iov_base);

        buffpos += v.iov_len;
    }

    evbuffer_add_buffer(dst, src);
    return BEV_OK;
}

/**
 * Setup a new event base and a connection listener to fire _accept_callback
 * and start listening
 */
int main(int argc, char **argv)
{
    jw_err    err;
    jw_htable *config = NULL;
    jw_stream *stream = NULL;
    
    struct event_base *eventBase        = NULL;
    struct event      *closeStreamEvent = NULL;
    struct timeval     delay            = {5, 0};

    // parameters to retrieve from the commandline
    char *jidStr     = NULL;
    char *password   = NULL;
    char *streamType = NULL;
    char *hostname   = NULL;
    char *port       = NULL;
    char *uri        = NULL;
    int   verbosity  = JW_LOG_WARN;

    // set initial logging level
    jw_log_set_level(verbosity);
    
    if (!parseCommandline(argc, argv,
                          &jidStr, &password, &streamType, &hostname,
                          &port, &uri, &verbosity))
    {
        return 1;
    }
    
    // set final logging level
    jw_log_set_level(verbosity);
    
    eventBase = event_base_new();
    if (!eventBase)
    {
        jw_log(JW_LOG_ERROR, "could not initialize event base");
        return 1;
    }

    if (!jw_htable_create(7, jw_strcase_hashcode, jw_strcase_compare,
                          &config, &err))
    {
        jw_log_err(JW_LOG_ERROR, &err, "could not create hashtable");
        return 1;
    }

    if (!jw_htable_put(config, JW_WORKQ_CONFIG_SELECTOR, eventBase, NULL, &err))
    {
        jw_log_err(JW_LOG_ERROR, &err, "error populating configuration htable");
        return 1;
    }

    jw_workq *workq;
    if (!jw_workq_create(config, &workq, &err))
    {
        jw_log_err(JW_LOG_ERROR, &err, "could not create workq");
        return 1;
    }

    // extract the domain from the jid
    jw_jid_ctx *jidCtx;
    if (!jw_jid_context_create(0, &jidCtx, &err))
    {
        jw_log_err(JW_LOG_ERROR, &err, "could not create jid context");
        return 1;
    }

    jw_jid *jid;
    if (!jw_jid_create(jidCtx, jidStr, &jid, &err))
    {
        jw_log_err(JW_LOG_ERROR, &err, "could not parse jid: '%s'", jidStr);
        return 1;
    }

    char *domain = (char *)jw_jid_get_domain(jid);
    
    if (!jw_htable_put(config, JW_STREAM_CONFIG_USERJID, jidStr,   NULL, &err)
     || !jw_htable_put(config, JW_STREAM_CONFIG_LOG_LABEL, jidStr, NULL, &err)
     || !jw_htable_put(config, JW_STREAM_CONFIG_USERPW,  password, NULL, &err)
     || !jw_htable_put(config, JW_STREAM_CONFIG_NAMESPACE,
                                                  "jabber:client", NULL, &err)
     || !jw_htable_put(config, JW_STREAM_CONFIG_DOMAIN,  domain,   NULL, &err)
     || (hostname &&
         !jw_htable_put(config, JW_STREAM_CONFIG_HOST,   hostname, NULL, &err))
     || (port &&
         !jw_htable_put(config, JW_STREAM_CONFIG_PORT,   port,     NULL, &err))
     || (uri &&
         !jw_htable_put(config, JW_STREAM_CONFIG_URI,    uri,      NULL, &err)))
    {
        jw_log_err(JW_LOG_ERROR, &err, "error populating configuration htable");
        return 1;
    }

    if (!streamType ||
        0 == strncasecmp(streamType,
                         JW_CLIENT_CONFIG_STREAM_TYPE_SOCKET,
                         strlen(JW_CLIENT_CONFIG_STREAM_TYPE_SOCKET)))
    {
        if (!jw_stream_socket_create(workq, &stream, &err))
        {
            jw_log_err(JW_LOG_ERROR, &err, "could not create socket stream");
            return 1;
        }
    }
    else if (0 == jw_strncasecmp(streamType,
                                 JW_CLIENT_CONFIG_STREAM_TYPE_BOSH,
                                 strlen(JW_CLIENT_CONFIG_STREAM_TYPE_BOSH)))
    {
        if (!jw_stream_bosh_create(workq, &stream, &err))
        {
            jw_log_err(JW_LOG_ERROR, &err, "could not create bosh stream");
            return 1;
        }
    }
    else
    {
        jw_log(JW_LOG_ERROR, "invalid stream type: '%s'", streamType);
        return 1;
    }

#define EVT_BIND(ename, cb, arg) \
    jw_event_bind(\
        jw_stream_event(stream, (ename)), \
        (cb), (arg), NULL)

    EVT_BIND(JW_STREAM_EVENT_OPENED,   onConnected,        config);
    EVT_BIND(JW_STREAM_EVENT_CLOSED,   onDisconnected,     NULL);
    EVT_BIND(JW_STREAM_EVENT_CLOSED,   onDestroyed,        NULL);
    EVT_BIND(JW_STREAM_EVENT_ELEMRECV, onElementsReceived, NULL);
    EVT_BIND(JW_STREAM_EVENT_ELEMSENT, onElementsSent,     NULL);

#undef EVT_BIND

    printf("opening stream\n");
    jw_stream_open(stream, config, NULL);

    jw_stream_add_filter(stream,
                         log_input,
                         log_output,
                         BEV_OPT_CLOSE_ON_FREE,
                         NULL,
                         NULL,
                         NULL);

    jw_stream_add_filter(stream,
                         log2_input,
                         log2_output,
                         BEV_OPT_CLOSE_ON_FREE,
                         NULL,
                         NULL,
                         NULL);

    closeStreamEvent = event_new(eventBase,
                                 -1,
                                 EV_TIMEOUT,
                                 closeStreamCallback,
                                 (void*)stream);
    event_add(closeStreamEvent, &delay);

    printf("starting dispatch loop\n");
    event_base_dispatch(eventBase);

    printf("returning from dispatch loop\n");
    jw_stream_destroy(stream);
    event_base_loop(eventBase, EVLOOP_NONBLOCK);
    event_base_free(eventBase);

    jw_workq_destroy(workq);
    jw_htable_destroy(config);

    printf("Have a great day!\n");
    return 0;
}
