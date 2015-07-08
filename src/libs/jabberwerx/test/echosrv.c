/**
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

/**
 * A simple xml stanza echo server implemented using libevent.  Accepts stream
 * connections on a network socket and echos XML back to the connected clients.
 * Note that both the client and this server can share the same libevent event
 * loop.
 */

#include "echosrv.h"
#include "stanza_defines.h"

#include <assert.h>
#include <string.h>
#include <event2/listener.h>
#include <jabberwerx/util/log.h>
#include <jabberwerx/jabberwerx.h>


// multi-family socket end-point address
// from: http://stackoverflow.com/questions/1429645/how-to-cast-sockaddr-storage-and-avoid-breaking-strict-aliasing-rules
typedef union address
{
    struct sockaddr         sa;
    struct sockaddr_in      sa_in;
    struct sockaddr_in6     sa_in6;
    struct sockaddr_storage sa_stor;
} address_t;

struct _jw_test_echosrv
{
    jw_workq              *workq;
    jw_workq_item         *close_item;
    struct evconnlistener *connListener4;
    struct evconnlistener *connListener6;
    uint16_t               port;
    jw_test_echosrv_core   echosrv_core;
    struct bufferevent    *bev;
};


#define PUSH_ECHOSRV_NDC int _ndcDepth = _push_echosrv_ndc(__func__)
#define POP_ECHOSRV_NDC jw_log_pop_ndc(_ndcDepth)
static int _push_echosrv_ndc(const char *entrypoint)
{
    assert(entrypoint);
    return jw_log_push_ndc("echosrv entrypoint=%s", entrypoint);
}


static void _close_cb(jw_workq_item *item, void *arg)
{
    UNUSED_PARAM(item);
    
    PUSH_ECHOSRV_NDC;
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    jw_test_echosrv echosrv = arg;
    assert(echosrv);
    assert(echosrv->bev);
    
    bufferevent_free(echosrv->bev);
    echosrv->bev = NULL;

    POP_ECHOSRV_NDC;
}

static void _schedule_close(jw_test_echosrv echosrv)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(echosrv);

    if (!jw_workq_item_is_scheduled(echosrv->close_item))
    {
        jw_err err;
        if (!jw_workq_item_append(echosrv->close_item, &err))
        {
            jw_log_err(JW_LOG_ERROR, &err, "failed to append close item");
            assert(false);
        }
    }
}

static bool _handle_cmd_cb(jw_dom_node  *stanza,
                           const char   *cmd,
                           jw_dom_node  *cmd_data,
                           jw_dom_node **reply,
                           void         *arg,
                           jw_err       *err)
{
    UNUSED_PARAM(stanza);
    UNUSED_PARAM(err);

    PUSH_ECHOSRV_NDC;
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(reply);
    jw_test_echosrv echosrv = arg;
    assert(echosrv);

    if (0 != jw_strcmp(cmd, JW_ECHOSRV_CMD_CLOSE))
    {
        POP_ECHOSRV_NDC;
        return false;
    }

    _schedule_close(echosrv);
    *reply = cmd_data;

    POP_ECHOSRV_NDC;
    return true;
}

static void _buffer_read_cb(struct bufferevent *bev, void *arg)
{
    PUSH_ECHOSRV_NDC;
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    jw_test_echosrv echosrv = arg;
    assert(echosrv);
    struct evbuffer *input  = bufferevent_get_input(bev);
    struct evbuffer *output = bufferevent_get_output(bev);

    jw_err err;
    if (!_jw_test_echosrv_core_submit(
                echosrv->echosrv_core, input, output, &err))
    {
        jw_log_err(JW_LOG_WARN, &err, "echosrv_core_submit failed");

        size_t remaining = evbuffer_get_length(input);
        if (0 < remaining && 0 != evbuffer_drain(input, remaining))
        {
            jw_log(JW_LOG_WARN, "failed to drain remaining input");
        }

        _schedule_close(echosrv);
    }

    POP_ECHOSRV_NDC;
}

static void _accept_callback(struct evconnlistener *l,
                             evutil_socket_t        fd,
                             struct sockaddr       *addr,
                             int                    socklen,
                             void                  *arg)
{
    PUSH_ECHOSRV_NDC;
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    UNUSED_PARAM(l);
    UNUSED_PARAM(addr);
    UNUSED_PARAM(socklen);

    jw_test_echosrv echosrv = arg;
    assert(echosrv);

    jw_log(JW_LOG_DEBUG, "accepting echosrv connection");
    assert(!echosrv->bev);
    echosrv->bev = bufferevent_socket_new(
            jw_workq_get_selector(echosrv->workq), fd, BEV_OPT_CLOSE_ON_FREE);
    if (!echosrv->bev)
    {
        jw_log(JW_LOG_WARN, "failed to create socket bufferevent");
        evutil_closesocket(fd);
        return;
    }

    bufferevent_setcb(echosrv->bev, _buffer_read_cb, NULL, NULL, echosrv);
    if (0 != bufferevent_enable(echosrv->bev, EV_READ|EV_WRITE))
    {
        jw_log(JW_LOG_WARN, "failed to enable buffer events");
        bufferevent_free(echosrv->bev);
        echosrv->bev = NULL;
        return;
    }

    POP_ECHOSRV_NDC;
}


///////////////////////////////////////////////////////
// public API
//

bool _jw_test_echosrv_create(jw_workq        *workq,
                             jw_test_echosrv *ret_echosrv,
                             jw_err          *err)
{
    PUSH_ECHOSRV_NDC;
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(workq);
    assert(ret_echosrv);

    bool retval = false;

    jw_test_echosrv echosrv =
            jw_data_calloc(1, sizeof(struct _jw_test_echosrv));
    if (NULL == echosrv)
    {
        JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
        goto jw_echosrv_create_done_label;
    }
    echosrv->workq = workq;

    if (!jw_workq_item_create(echosrv->workq, _close_cb,
                              &echosrv->close_item, err))
    {
        goto jw_echosrv_create_done_label;
    }
    jw_workq_item_set_data(echosrv->close_item, echosrv, NULL);

    // sizea is an integer to match libevent function signatures
    address_t addr;
    int sizea = sizeof(address_t);
    memset(&addr, 0, sizea);

    // trivial (and platform independent) connection for localhost
    if (0 != evutil_parse_sockaddr_port("127.0.0.1", &addr.sa, &sizea))
    {
        jw_log(JW_LOG_ERROR, "could not initialize sockaddr");
        JABBERWERX_ERROR(err, JW_ERR_SOCKET_CONNECT);
        goto jw_echosrv_create_done_label;
    }

    struct event_base *evbase = jw_workq_get_selector(workq);
    echosrv->connListener4 =
            evconnlistener_new_bind(evbase, _accept_callback, echosrv,
                                    LEV_OPT_CLOSE_ON_FREE,
                                    -1, &addr.sa, sizea);
    if (!echosrv->connListener4)
    {
        jw_log(JW_LOG_ERROR, "could not create inet4 socket listener");
        JABBERWERX_ERROR(err, JW_ERR_SOCKET_CONNECT);
        goto jw_echosrv_create_done_label;
    }

    // get the port that bind chose
    address_t bindAddr;
    socklen_t bindAddrLen = sizeof(bindAddr);
    if (0 != getsockname(evconnlistener_get_fd(echosrv->connListener4),
                         &bindAddr.sa, &bindAddrLen))
    {
        jw_log(JW_LOG_ERROR, "could not identify bound port");
        JABBERWERX_ERROR(err, JW_ERR_SOCKET_CONNECT);
        goto jw_echosrv_create_done_label;
    }
    echosrv->port = ntohs(bindAddr.sa_in.sin_port);

    // bind v6 address
    sizea = sizeof(address_t);
    memset(&addr, 0, sizea);

    if (0 == evutil_parse_sockaddr_port(
             "[::1]", &addr.sa, &sizea))
    {
        addr.sa_in6.sin6_port = bindAddr.sa_in.sin_port;
        echosrv->connListener6 =
                evconnlistener_new_bind(evbase, _accept_callback, echosrv,
                                        LEV_OPT_CLOSE_ON_FREE,
                                        -1, &addr.sa, sizea);
    }

    if (!_jw_test_echosrv_core_create(&echosrv->echosrv_core, err))
    {
        goto jw_echosrv_create_done_label;
    }
    _jw_test_echosrv_core_set_cmd_handler(
                echosrv->echosrv_core, _handle_cmd_cb, echosrv);

    *ret_echosrv = echosrv;

    jw_log(JW_LOG_DEBUG,
           "successfully started echosrv on 127.0.0.1:%u", echosrv->port);
    if (echosrv->connListener6)
    {
        jw_log(JW_LOG_DEBUG,
               "successfully started echosrv on [::1]:%u", echosrv->port);
    }

    retval = true;

jw_echosrv_create_done_label:
    if (!retval && echosrv) { _jw_test_echosrv_destroy(echosrv); }
    POP_ECHOSRV_NDC;
    return retval;
}

void _jw_test_echosrv_destroy(jw_test_echosrv echosrv)
{
    PUSH_ECHOSRV_NDC;
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    if (echosrv->close_item)
    {
        jw_workq_item_destroy(echosrv->close_item);
    }
    if (echosrv->connListener4)
    {
        evconnlistener_free(echosrv->connListener4);
    }
    if (echosrv->connListener6)
    {
        evconnlistener_free(echosrv->connListener6);
    }
    if (echosrv->echosrv_core)
    {
        _jw_test_echosrv_core_destroy(echosrv->echosrv_core);
    }
    if (echosrv->bev)
    {
        bufferevent_free(echosrv->bev);
    }

    jw_data_free(echosrv);

    POP_ECHOSRV_NDC;
}

uint16_t _jw_test_echosrv_get_port(jw_test_echosrv echosrv)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(echosrv);
    return echosrv->port;
}

jw_test_echosrv_core _jw_test_echosrv_get_echosrv_core(jw_test_echosrv echosrv)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(echosrv);
    return echosrv->echosrv_core;
}
