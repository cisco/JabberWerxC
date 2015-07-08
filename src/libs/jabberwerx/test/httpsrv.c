/**
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

#include "httpsrv.h"
#include <jabberwerx/util/mem.h>
#include <jabberwerx/util/log.h>
#include <event2/buffer.h>
#include <event2/http.h>
#include <assert.h>
#include <string.h>

struct _jw_httpsrv
{
    struct evhttp   *http;
    uint16_t         port;
    bool             use_custom_response;
    int              next_status;
    struct evbuffer *next_body;
};

static void _request_cb(struct evhttp_request *req, void *arg)
{
    jw_httpsrv httpsrv = arg;
    assert(httpsrv);
    evhttp_send_reply(req,
        httpsrv->use_custom_response ? httpsrv->next_status : 200,
        NULL,
        httpsrv->use_custom_response ? httpsrv->next_body : NULL);
    httpsrv->use_custom_response = false;
}

bool jw_httpsrv_create(struct event_base *evbase,
                       jw_httpsrv        *rethttpsrv,
                       jw_err            *err)
{
    bool retval = false;

    jw_httpsrv httpsrv = jw_data_malloc(sizeof(struct _jw_httpsrv));
    if (NULL == httpsrv)
    {
        JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
        goto jw_httpsrv_create_done_label;
    }
    memset(httpsrv, 0, sizeof(struct _jw_httpsrv));

    httpsrv->http = evhttp_new(evbase);
    if (NULL == httpsrv->http)
    {
        JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
        goto jw_httpsrv_create_done_label;
    }

    httpsrv->next_body = evbuffer_new();
    if (NULL == httpsrv->next_body)
    {
        JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
        goto jw_httpsrv_create_done_label;
    }

    evhttp_set_gencb(httpsrv->http, _request_cb, httpsrv);

    struct evhttp_bound_socket *handle =
        evhttp_bind_socket_with_handle(httpsrv->http, "127.0.0.1", 0);
    if (NULL == handle)
    {
        jw_log(JW_LOG_WARN, "failed to bind http server to port");
        JABBERWERX_ERROR(err, JW_ERR_INVALID_STATE);
        goto jw_httpsrv_create_done_label;
    }

    evutil_socket_t fd = evhttp_bound_socket_get_fd(handle);
    struct sockaddr_storage ss;
    ev_socklen_t socklen = sizeof(ss);
    memset(&ss, 0, sizeof(ss));

    if (0 != getsockname(fd, (struct sockaddr *)&ss, &socklen))
    {
        assert(false);
    }
    if (AF_INET == ss.ss_family)
    {
        httpsrv->port = ntohs(((struct sockaddr_in*)&ss)->sin_port);
    }
    else if (AF_INET6 == ss.ss_family)
    {
        httpsrv->port = ntohs(((struct sockaddr_in6*)&ss)->sin6_port);
    }
    else
    {
        assert(false);
    }

    *rethttpsrv = httpsrv;

    jw_log(JW_LOG_VERBOSE,
           "successfully started httpsrv on 127.0.0.1:%u", httpsrv->port);

    retval = true;

jw_httpsrv_create_done_label:
    if (!retval && httpsrv) { jw_httpsrv_destroy(httpsrv); }
    return retval;
}

void jw_httpsrv_destroy(jw_httpsrv httpsrv)
{
    assert(httpsrv);
    if (httpsrv->http)
    {
        evhttp_free(httpsrv->http);
    }
    if (httpsrv->next_body)
    {
        evbuffer_free(httpsrv->next_body);
    }
    jw_data_free(httpsrv);
}

uint16_t jw_httpsrv_get_port(jw_httpsrv httpsrv)
{
    assert(httpsrv);
    return httpsrv->port;
}

bool jw_httpsrv_set_next_response(
        jw_httpsrv httpsrv, int status_code, const char *body)
{
    assert(httpsrv);

    if (0 != evbuffer_drain(httpsrv->next_body,
                            evbuffer_get_length(httpsrv->next_body)))
    {
        jw_log(JW_LOG_WARN, "failed to drain response buffer");
        return false;
    }

    if (0 > evbuffer_add_printf(httpsrv->next_body, "%s", body))
    {
        jw_log(JW_LOG_WARN, "failed to write to response buffer");
        return false;
    }

    httpsrv->next_status         = status_code;
    httpsrv->use_custom_response = true;

    return true;
}
