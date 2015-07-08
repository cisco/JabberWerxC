/**
 * \file
 * \brief
 * This code is pulled out of bosh.c for the sake of modularity and clarity.
 * Callbacks are passed in from bosh.c and called from here synchronously.
 *
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

#include <assert.h>
#include <string.h>

// leave some includes outside this ifndef since empty files are not compilable
#ifndef JABBERWERX_NO_BOSH

#include <curl/curl.h>
#include "../include/bosh_conn_int.h"
#include <jabberwerx/util/serializer.h>
#include <jabberwerx/util/log.h>


#define CONNECT_TIMEOUT 30   // in seconds
#define MS_PER_SECOND   1000
#define MS_PER_USEC     1000


struct _bosh_conn_int
{
    _bosh_conn_ctx   ctx;      // parent context
    CURL            *easy;     // curl "easy" request handle; reusable
    struct evbuffer *req_buf;  // holds serialized body data for active req
    struct evbuffer *resp_buf; // holds server response
    int              req_arg;  // user val passed to response callback
    struct event    *sock_ev;  // event tied to active request socket
    bool             active;   // true while req is registered with multi
};

struct _bosh_conn_ctx_int
{
    struct event_base *evbase;      // libevent selector
    const char        *log_label;   // label to use in NDC log entries
    CURLM             *multi;       // curl "multi" handle
    int                num_active;  // maintained by curl during socket action
    struct event      *timeout_ev;  // used by curl to multiplex all timeouts
    struct curl_slist *header_list; // BOSH headers in curl format
    void              *cb_arg;      // passed to the callbacks

    _on_response_cb response_cb;      // called on server response
    _on_error_cb    error_cb;         // called on error
};

static struct _bosh_conn_unit_test_fns *_test_fns = NULL;
void _bosh_conn_replace_impl(struct _bosh_conn_unit_test_fns* fns)
{
    if (fns)
    {
        assert(fns->conn_create);
        assert(fns->conn_destroy);
        assert(fns->conn_is_active);
        assert(fns->conn_send_request);
        assert(fns->context_create);
        assert(fns->context_destroy);
        assert(fns->context_get_num_active);
        assert(fns->context_set_label);
    }
    _test_fns = fns;
}

// assumes a variable named "conn_ctx" of the appropriate type has been defined
#define PUSH_CONN_NDC int _ndcDepth = _push_conn_ndc(conn_ctx, __func__)
#define POP_CONN_NDC jw_log_pop_ndc(_ndcDepth)
static int _push_conn_ndc(_bosh_conn_ctx conn_ctx, const char *entrypoint)
{
    assert(entrypoint);

    const char *label = "";
    if (conn_ctx && conn_ctx->log_label)
    {
        label = conn_ctx->log_label;
    }

    return jw_log_push_ndc(
            "bosh_conn label=%s; entrypoint=%s", label, entrypoint);
}

// check curl status codes; sets err and returns false on error
static bool _check_curl_mcode(CURLMcode curl_code, jw_err *err)
{
    JW_LOG_TRACE_FUNCTION("curl_code=%d", curl_code);

    if (CURLM_OK == curl_code || CURLM_CALL_MULTI_SOCKET == curl_code)
    {
        return true;
    }

    const char *s;
    switch (curl_code)
    {
    case CURLM_BAD_HANDLE:
        s = "CURLM_BAD_HANDLE";
        JABBERWERX_ERROR(err, JW_ERR_INVALID_STATE);
        break;
    case CURLM_BAD_EASY_HANDLE:
        s = "CURLM_BAD_EASY_HANDLE";
        JABBERWERX_ERROR(err, JW_ERR_INVALID_STATE);
        break;
    case CURLM_OUT_OF_MEMORY:
        s = "CURLM_OUT_OF_MEMORY";
        JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
        break;
    case CURLM_INTERNAL_ERROR:
        s = "CURLM_INTERNAL_ERROR";
        JABBERWERX_ERROR(err, JW_ERR_INVALID_STATE);
        break;
    case CURLM_BAD_SOCKET:
        s = "CURLM_BAD_SOCKET";
        JABBERWERX_ERROR(err, JW_ERR_SOCKET_CONNECT);
        break;
    case CURLM_UNKNOWN_OPTION:
        s = "CURLM_UNKNOWN_OPTION";
        JABBERWERX_ERROR(err, JW_ERR_INVALID_STATE);
        break;
    default:
        s = "unknown error code";
        JABBERWERX_ERROR(err, JW_ERR_INVALID_STATE);
        break;
    }

    jw_log(JW_LOG_WARN, "curl: %s", s);
    return false;
}

// check for completed transfers, remove them from the multi handle, and call
// the completion callback
static bool _check_multi_info(_bosh_conn_ctx conn_ctx, jw_err *err)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(conn_ctx);

    CURLMsg *msg;
    int      msgs_left;
    while ((msg = curl_multi_info_read(conn_ctx->multi, &msgs_left)))
    {
        if (CURLMSG_DONE != msg->msg)
        {
            jw_log(JW_LOG_WARN, "unknown curl message type: %d", msg->msg);
            continue;
        }

        CURL *easy          = msg->easy_handle;
        long  response_code = 0;
        if (CURLE_OK !=
                curl_easy_getinfo(easy, CURLINFO_RESPONSE_CODE, &response_code))
        {
            jw_log(JW_LOG_WARN, "unable to retrieve http response code");
            JABBERWERX_ERROR(err, JW_ERR_INVALID_STATE);
            return false;
        }

        // if the response code is still 0, check for a proxy-level failure
        if (0 == response_code && CURLE_OK !=
             curl_easy_getinfo(easy, CURLINFO_HTTP_CONNECTCODE, &response_code))
        {
            jw_log(JW_LOG_WARN, "unable to retrieve proxy response code");
            JABBERWERX_ERROR(err, JW_ERR_INVALID_STATE);
            return false;
        }

        _bosh_conn conn = NULL;
        if (CURLE_OK != curl_easy_getinfo(easy, CURLINFO_PRIVATE, (char **)&conn))
        {
            jw_log(JW_LOG_WARN, "unable to retrieve private pointer");
            JABBERWERX_ERROR(err, JW_ERR_INVALID_STATE);
            return false;
        }
        assert(conn);
        assert(conn->easy == easy);
        assert(conn->active);
        
        jw_log(JW_LOG_DEBUG,
               "request complete (easy=%p; req_arg=%d; result=%ld)",
               easy, conn->req_arg, response_code);

        if (!_check_curl_mcode(
                curl_multi_remove_handle(conn_ctx->multi, conn->easy), err))
        {
            return false;
        }

        // clean up resources and mark connection as inactive so it can be
        // reused directly from the response callback
        if (conn->req_buf)
        {
            evbuffer_free(conn->req_buf);
            conn->req_buf = NULL;
        }
        struct evbuffer *resp_buf = conn->resp_buf;
        conn->resp_buf = NULL;
        conn->active = false;

        conn_ctx->response_cb(resp_buf, response_code,
                              conn->req_arg, conn_ctx->cb_arg);

        if (resp_buf)
        {
            evbuffer_free(resp_buf);
        }
    }

    return true;
}

// called by libevent when we get a socket event
static void _curl_event_cb(int fd, short events, void *arg)
{
    _bosh_conn_ctx conn_ctx = arg;

    PUSH_CONN_NDC;
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(conn_ctx);
    // map libevent constants to curl constants
    int action = (events & EV_READ  ? CURL_CSELECT_IN  : 0) |
                 (events & EV_WRITE ? CURL_CSELECT_OUT : 0);

    jw_err    err;
    CURLMcode rc = curl_multi_socket_action(
            conn_ctx->multi, fd, action, &conn_ctx->num_active);
    if (!_check_curl_mcode(rc, &err))
    {
        goto _curl_event_cb_fail_label;
    }

    if (!_check_multi_info(conn_ctx, &err))
    {
        goto _curl_event_cb_fail_label;
    }

    if (0 >= conn_ctx->num_active
     && 0 != evtimer_pending(conn_ctx->timeout_ev, NULL))
    {
        jw_log(JW_LOG_DEBUG, "no more pending transfers; killing curl timeout");
        if (0 != evtimer_del(conn_ctx->timeout_ev))
        {
            jw_log(JW_LOG_WARN, "failed to remove curl event timer");
            JABBERWERX_ERROR(&err, JW_ERR_INVALID_STATE);
            goto _curl_event_cb_fail_label;
        }
    }

    goto _curl_event_cb_done_label;

_curl_event_cb_fail_label:
    conn_ctx->error_cb(err.code, conn_ctx->cb_arg);
_curl_event_cb_done_label:
    POP_CONN_NDC;
}

static void _do_multi_socket_action(_bosh_conn_ctx conn_ctx)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(conn_ctx);

    // tell curl that a timeout has occurred
    jw_err    err;
    CURLMcode rc = curl_multi_socket_action(
            conn_ctx->multi, CURL_SOCKET_TIMEOUT, 0, &conn_ctx->num_active);
    if (!_check_curl_mcode(rc, &err))
    {
        goto _do_multi_socket_action_fail_label;
    }

    // test to see if we have any connection status changes to react to
    if (!_check_multi_info(conn_ctx, &err))
    {
        goto _do_multi_socket_action_fail_label;
    }

    return;

_do_multi_socket_action_fail_label:
    conn_ctx->error_cb(err.code, conn_ctx->cb_arg);
}

// called by libevent when our curl-directed timeout expires
static void _curl_timer_cb(int fd, short events, void *arg)
{
    UNUSED_PARAM(fd);
    UNUSED_PARAM(events);

    _bosh_conn_ctx conn_ctx = arg;

    PUSH_CONN_NDC;
    JW_LOG_TRACE_FUNCTION_NO_ARGS;
    _do_multi_socket_action(conn_ctx);
    POP_CONN_NDC;
}

// called by curl whenever the time until the next significant event changes.
// for example, when one connection times out or the next connection that would
// time out completes, this function is called with the time until the next
// timeout deadline.
static int _curl_set_timer_cb(CURLM *multi, long timeout_ms, void *arg)
{
    UNUSED_PARAM(multi);

    _bosh_conn_ctx conn_ctx = arg;

    PUSH_CONN_NDC;
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(conn_ctx);
    if (0 != evtimer_del(conn_ctx->timeout_ev))
    {
        jw_log(JW_LOG_WARN, "failed to remove curl event timer");
        conn_ctx->error_cb(JW_ERR_INVALID_STATE, conn_ctx->cb_arg);
    }
    else if (-1 < timeout_ms) // add/re-add timer if requested to do so
    {
        assert(conn_ctx->timeout_ev);
        
        struct timeval timeout;
        timeout.tv_sec = timeout_ms / MS_PER_SECOND;
        timeout.tv_usec = (timeout_ms % MS_PER_SECOND) * MS_PER_USEC;

        jw_log(JW_LOG_DEBUG, "setting curl timer to %ld ms", timeout_ms);
        if (0 != evtimer_add(conn_ctx->timeout_ev, &timeout))
        {
            jw_log(JW_LOG_WARN, "failed to add curl event timer");
            conn_ctx->error_cb(JW_ERR_INVALID_STATE, conn_ctx->cb_arg);
        }
    }
    else
    {
        jw_log(JW_LOG_DEBUG, "no timeout requested; not setting curl timer");
    }

    POP_CONN_NDC;
    return 0;
}

// configure request socket
static bool _curl_sock_set(
        _bosh_conn conn, curl_socket_t fd, int what, jw_err *err)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(conn);
    _bosh_conn_ctx conn_ctx = conn->ctx;
    assert(conn_ctx);

    // map curl constants to libevent constants
    int events = (what & CURL_POLL_IN  ? EV_READ  : 0) |
                 (what & CURL_POLL_OUT ? EV_WRITE : 0) | EV_PERSIST;

    if (!conn->sock_ev)
    {
        conn->sock_ev =
            event_new(conn_ctx->evbase, fd, events, _curl_event_cb, conn_ctx);
        if (NULL == conn->sock_ev)
        {
            JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
            return false;
        }
    }
    else
    {
        if (0 != event_del(conn->sock_ev))
        {
            JABBERWERX_ERROR(err, JW_ERR_INVALID_STATE);
            return false;
        }

        if (0 != event_assign(conn->sock_ev, conn_ctx->evbase,
                              fd, events, _curl_event_cb, conn_ctx))
        {
            JABBERWERX_ERROR(err, JW_ERR_INVALID_STATE);
            return false;
        }
    }

    if (EV_PERSIST != events && 0 != event_add(conn->sock_ev, NULL))
    {
        JABBERWERX_ERROR(err, JW_ERR_INVALID_STATE);
        return false;
    }

    return true;
}

// called when there is activity on the socket (via _curl_event_cb)
static const char *WHATSTR[CURL_POLL_REMOVE + 1] =
        { "NONE", "IN", "OUT", "INOUT", "REMOVE" };
static int _curl_sock_cb(
        CURL *easy, curl_socket_t sockfd, int what, void *userp, void *sockp)
{
    UNUSED_PARAM(sockp);

    _bosh_conn_ctx conn_ctx = userp;

    PUSH_CONN_NDC;
    const char *whatstr =
        (0 > what || CURL_POLL_REMOVE < what) ? "unknown" : WHATSTR[what];
    JW_LOG_TRACE_FUNCTION("curl socket callback: easy=%p; sockfd=%d; what=%s",
           easy, sockfd, whatstr);
    assert(conn_ctx);

    _bosh_conn conn = NULL;
    if (CURLE_OK != curl_easy_getinfo(easy, CURLINFO_PRIVATE, (char **)&conn))
    {
        jw_log(JW_LOG_WARN, "unable to retrieve private curl data");
        conn_ctx->error_cb(JW_ERR_INVALID_STATE, conn_ctx->cb_arg);
        goto _curl_sock_cb_done_label;
    }
    assert(conn);

    jw_err err;
    jw_log(JW_LOG_DEBUG, "socket action for req_arg=%d now %s",
           conn->req_arg, whatstr);
    if (!_curl_sock_set(conn, sockfd, what, &err))
    {
        conn_ctx->error_cb(err.code, conn_ctx->cb_arg);
    }

_curl_sock_cb_done_label:
    POP_CONN_NDC;
    return 0; // this callback must return 0 as required by curl
}

// called from curl_multi_socket_action when libevent tells curl that there
// is data ready to be written to the connection
static size_t _curl_read_cb(void *ptr, size_t size, size_t nmemb, void *arg)
{
    _bosh_conn conn = arg;
    assert(conn);
    _bosh_conn_ctx conn_ctx = conn->ctx;

    PUSH_CONN_NDC;
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(conn_ctx);

    // this copy is currently unavoidable.  it would be nice to have a libcurl
    // API that takes bufferevents all the way down to the socket level
    assert(conn->req_buf);
    size_t copied = evbuffer_copyout(conn->req_buf, ptr, size*nmemb);
    if (0 < copied)
    {
        if (0 != evbuffer_drain(conn->req_buf, copied))
        {
            jw_log(JW_LOG_WARN, "failed to drain evbuffer");
            conn_ctx->error_cb(JW_ERR_INVALID_STATE, conn_ctx->cb_arg);
            copied = 0;
        }
    }

    jw_log(JW_LOG_DEBUG,
        "sending %zd bytes of request data (%zd bytes remaining) on req_arg=%d",
        copied, evbuffer_get_length(conn->req_buf), conn->req_arg);

    POP_CONN_NDC;
    return copied;
}

// called from curl_multi_socket_action when libevent tells curl that there
// is data ready to be read from the connection
static size_t _curl_write_cb(void *ptr, size_t size, size_t nmemb, void *arg)
{
    _bosh_conn conn = arg;
    assert(conn);
    _bosh_conn_ctx conn_ctx = conn->ctx;

    PUSH_CONN_NDC;
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(conn_ctx);
    size_t data_len = size * nmemb;

    jw_log(JW_LOG_DEBUG, "receiving %zd bytes of response data on req_arg=%d",
           data_len, conn->req_arg);

    // lazily create the response buffer and record the response chunk.  we'll
    // call the the callback once we're sure we have the complete response
    if (!conn->resp_buf && !(conn->resp_buf = evbuffer_new()))
    {
        jw_log(JW_LOG_WARN, "could not allocate response buffer");
        conn_ctx->error_cb(JW_ERR_NO_MEMORY, conn_ctx->cb_arg);
    }
    else if (0 != evbuffer_add(conn->resp_buf, ptr, data_len))
    {
        jw_log(JW_LOG_WARN, "could not add to response buffer");
        conn_ctx->error_cb(JW_ERR_NO_MEMORY, conn_ctx->cb_arg);
    }

    POP_CONN_NDC;
    return data_len;
}

// convenience function for setting a curl option that takes an integer
static bool _curl_setopt_i(CURL *easy, CURLoption opt, int arg, jw_err *err)
{
    JW_LOG_TRACE_FUNCTION("easy=%p; opt=%d; arg=%d", easy, opt, arg);

    if (CURLE_OK != curl_easy_setopt(easy, opt, arg))
    {
        jw_log(JW_LOG_WARN, "failed to set curl option: %d", opt);
        JABBERWERX_ERROR(err, JW_ERR_INVALID_STATE);
        return false;
    }
    return true;
}

// convenience function for setting a curl option that takes a function pointer
#define _curl_setopt_f(easy, opt, arg, err) \
        _curl_setopt_f_int(easy, opt, (void (*)())arg, #arg, err)
static bool _curl_setopt_f_int(
     CURL *easy, CURLoption opt, void (*arg)(), const char *argstr, jw_err *err)
{
    JW_LOG_TRACE_FUNCTION("easy=%p; opt=%d; arg=%s", easy, opt, argstr);

    if (CURLE_OK != curl_easy_setopt(easy, opt, arg))
    {
        jw_log(JW_LOG_WARN, "failed to set curl option: %d", opt);
        JABBERWERX_ERROR(err, JW_ERR_INVALID_STATE);
        return false;
    }
    return true;
}

// convenience function for setting a curl option that takes a data pointer
#define _curl_setopt_p(easy, opt, arg, err) \
        _curl_setopt_p_int(easy, opt, (void *)arg, #arg, err)
static bool _curl_setopt_p_int(
        CURL *easy, CURLoption opt, void *arg, const char *argstr, jw_err *err)
{
    JW_LOG_TRACE_FUNCTION("easy=%p; opt=%d; arg=%s", easy, opt, argstr);

    if (CURLE_OK != curl_easy_setopt(easy, opt, arg))
    {
        jw_log(JW_LOG_WARN, "failed to set curl option: %d", opt);
        JABBERWERX_ERROR(err, JW_ERR_INVALID_STATE);
        return false;
    }
    return true;
}

// shuttles curl debug output to our logging system
static int _curl_debug_cb(
        CURL *easy, curl_infotype type, char *data, size_t len, void *arg)
{
    UNUSED_PARAM(arg);
    
    // no JW_LOG_TRACE_FUNCTION call since here it would just be spam

    jw_loglevel level = JW_LOG_DEBUG;
    const char *prefix;
    
    switch (type)
    {
    case CURLINFO_TEXT:       prefix = "";                  break;
    case CURLINFO_HEADER_IN:  prefix = "received header: "; break;
    case CURLINFO_HEADER_OUT: prefix = "sent header: ";     break;
    case CURLINFO_DATA_IN:    prefix = "received data: ";   break;
    case CURLINFO_DATA_OUT:   prefix = "sent data: ";       break;
        
    default:
        level  = JW_LOG_WARN;
        prefix = "unknown message type: ";
    }

    // convert multiline data into multiple single-line log messages
    if (level <= jw_log_get_level())
    {
        char *msg_start = NULL;
        for (char *msg_end = data; (size_t)(msg_end - data) < len; ++msg_end)
        {
            if ('\n' == *msg_end || '\r' == *msg_end)
            {
                if (NULL != msg_start)
                {
                    jw_log(level, "CURL(easy=%p): %s%.*s",
                           easy, prefix, (int)(msg_end - msg_start), msg_start);
                    msg_start = NULL;
                }
            }
            else if (NULL == msg_start)
            {
                msg_start = msg_end;
            }
        }

        if (NULL != msg_start)
        {
            jw_log(level, "CURL(easy=%p): %s%.*s",
                   easy, prefix, (int)(data + len - msg_start), msg_start);
        }
    }

    // this function is required to return 0
    return 0;
}


//
// API functions
//

bool _bosh_conn_context_create(
        struct event_base   *evbase,
        int                  conn_cache_size,
        _on_response_cb      response_cb,
        _on_error_cb         error_cb,
        void                *arg,
        _bosh_conn_ctx      *retctx,
        jw_err              *err)
{
    if (_test_fns)
    {
        return _test_fns->context_create(evbase, conn_cache_size, response_cb,
                                         error_cb, arg, retctx, err);
    }

    _bosh_conn_ctx conn_ctx = NULL;
    PUSH_CONN_NDC;
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(evbase);
    assert(0 <= conn_cache_size);
    assert(response_cb);
    assert(error_cb);
    assert(retctx);

    _bosh_conn_ctx ctx = jw_data_calloc(1, sizeof(struct _bosh_conn_ctx_int));
    if (!ctx)
    {
        jw_log(JW_LOG_WARN, "could not allocate bosh conn context");
        JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
        POP_CONN_NDC;
        return false;
    }

    // set the easy stuff
    ctx->evbase      = evbase;
    ctx->response_cb = response_cb;
    ctx->error_cb    = error_cb;
    ctx->cb_arg      = arg;

    // safely construct the header list (ugh)
    struct curl_slist *h = NULL;
    if (!(ctx->header_list = h = curl_slist_append(NULL, "Accept:"))
     || !curl_slist_append(h, "Accept-Encoding: gzip, deflate")
     || !curl_slist_append(h, "Content-Type: text/xml; charset=utf-8"))
    {
        jw_log(JW_LOG_WARN, "could not allocate bosh header list");
        JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
        goto _bosh_conn_context_create_fail_label;
    }

    // initialize the CURL multi handle
    if (NULL == (ctx->multi = curl_multi_init()))
    {
        jw_log(JW_LOG_WARN, "could not initialize curl multi handle");
        JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY); // probably
        goto _bosh_conn_context_create_fail_label;
    }

    // initialize the timer that backs the CURL timeouts
    if (NULL == (ctx->timeout_ev = evtimer_new(evbase, _curl_timer_cb, ctx)))
    {
        jw_log(JW_LOG_WARN, "could not allocate bosh conn timer");
        JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY); // probably
        goto _bosh_conn_context_create_fail_label;
    }

    // set options on multi handle
    // re: CURLMOPT_MAXCONNECTS: curl will open as many sockets as necessary to
    // handle any number of simultaneous requests, but once they are complete,
    // it will only keep this many connections open, ready for the next request
    if (!_check_curl_mcode(curl_multi_setopt(ctx->multi, CURLMOPT_SOCKETFUNCTION, _curl_sock_cb),      err)
     || !_check_curl_mcode(curl_multi_setopt(ctx->multi, CURLMOPT_SOCKETDATA,     ctx),                err)
     || !_check_curl_mcode(curl_multi_setopt(ctx->multi, CURLMOPT_TIMERFUNCTION,  _curl_set_timer_cb), err)
     || !_check_curl_mcode(curl_multi_setopt(ctx->multi, CURLMOPT_TIMERDATA,      ctx),                err)
     || !_check_curl_mcode(curl_multi_setopt(ctx->multi, CURLMOPT_MAXCONNECTS,    conn_cache_size),    err))
    {
        jw_log(JW_LOG_WARN, "failed to set curl multi option");
        goto _bosh_conn_context_create_fail_label;
    }

    jw_log(JW_LOG_DEBUG, "created bosh conn context %p", (void *)ctx);
    *retctx = ctx;
    POP_CONN_NDC;
    return true;

_bosh_conn_context_create_fail_label:
    _bosh_conn_context_destroy(ctx);
    POP_CONN_NDC;
    return false;
}

void _bosh_conn_context_destroy(_bosh_conn_ctx conn_ctx)
{
    if (_test_fns)
    {
        _test_fns->context_destroy(conn_ctx);
        return;
    }

    PUSH_CONN_NDC;
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(conn_ctx);
    if (conn_ctx->multi)
    {
        // prints error message on failure
        _check_curl_mcode(curl_multi_cleanup(conn_ctx->multi), NULL);
    }

    if (conn_ctx->timeout_ev)
    {
        event_free(conn_ctx->timeout_ev);
    }

    if (conn_ctx->header_list)
    {
        curl_slist_free_all(conn_ctx->header_list);
    }

    jw_data_free(conn_ctx);

    POP_CONN_NDC;
}

void _bosh_conn_context_set_label(_bosh_conn_ctx conn_ctx, const char *label)
{
    if (_test_fns)
    {
        _test_fns->context_set_label(conn_ctx, label);
        return;
    }

    JW_LOG_TRACE_FUNCTION_NO_ARGS;
    assert(conn_ctx);
    conn_ctx->log_label = label;
}

int _bosh_conn_context_get_num_active(_bosh_conn_ctx conn_ctx)
{
    if (_test_fns)
    {
        return _test_fns->context_get_num_active(conn_ctx);
    }

    JW_LOG_TRACE_FUNCTION_NO_ARGS;
    assert(conn_ctx);
    return conn_ctx->num_active;
}

bool _bosh_conn_create(_bosh_conn_ctx conn_ctx, _bosh_conn *conn, jw_err *err)
{
    if (_test_fns)
    {
        return _test_fns->conn_create(conn_ctx, conn, err);
    }

    PUSH_CONN_NDC;
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(conn_ctx);
    *conn = jw_data_calloc(1, sizeof(struct _bosh_conn_int));
    if (!*conn)
    {
        JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
        POP_CONN_NDC;
        return false;
    }

    (*conn)->ctx = conn_ctx;

    POP_CONN_NDC;
    return true;
}

void _bosh_conn_destroy(_bosh_conn conn)
{
    if (_test_fns)
    {
        _test_fns->conn_destroy(conn);
        return;
    }

    assert(conn);
    _bosh_conn_ctx conn_ctx = conn->ctx;

    PUSH_CONN_NDC;
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(conn_ctx);
    if (conn->easy)
    {
        CURL *easy = conn->easy;
        conn->easy = NULL;
        if (conn->active)
        {
            curl_multi_remove_handle(conn_ctx->multi, easy);
        }
        curl_easy_cleanup(easy);
    }
    conn->active = false;

    if (conn->sock_ev)
    {
        event_free(conn->sock_ev);
        conn->sock_ev = NULL;
    }

    if (conn->req_buf)
    {
        evbuffer_free(conn->req_buf);
        conn->req_buf = NULL;
    }

    if (conn->resp_buf)
    {
        evbuffer_free(conn->resp_buf);
        conn->resp_buf = NULL;
    }

    jw_data_free(conn);

    POP_CONN_NDC;
}

bool _bosh_conn_is_active(_bosh_conn conn)
{
    if (_test_fns)
    {
        return _test_fns->conn_is_active(conn);
    }

    JW_LOG_TRACE_FUNCTION_NO_ARGS;
    assert(conn);
    return conn->active;
}

bool _bosh_conn_send_request(
        _bosh_conn conn, const char *url, jw_dom_node *body,
        int timeout_ms, int req_arg, jw_err *err)
{
    if (_test_fns)
    {
        return _test_fns->conn_send_request(
                                conn, url, body, timeout_ms, req_arg, err);
    }

    assert(conn);
    _bosh_conn_ctx conn_ctx = conn->ctx;

    PUSH_CONN_NDC;
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    jw_err local_err;
    if (!err)
    {
        err = &local_err;
    }

    assert(conn_ctx);
    assert(!conn->active);
    assert(body);

    struct evbuffer *body_buf = evbuffer_new();
    if (!body_buf)
    {
        jw_log(JW_LOG_WARN, "could not allocate body buffer");
        JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
        goto _curl_send_request_fail_label;
    }

    if (conn->resp_buf)
    {
        evbuffer_free(conn->resp_buf);
        conn->resp_buf = NULL;
    }

    if (!jw_serialize_xml_buffer(body, body_buf, NULL, err))
    {
        jw_log_err(JW_LOG_WARN, err, "could not serialize XML");
        goto _curl_send_request_fail_label;
    }

    size_t req_len = evbuffer_get_length(body_buf);
    assert(0 < req_len);

    // lazily init request
    if (!conn->easy)
    {
        CURL *easy = curl_easy_init();
        if (!easy)
        {
            jw_log(JW_LOG_WARN, "could not initialize CURL easy handle");
            JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
            goto _curl_send_request_fail_label;
        }

        struct curl_slist *headers = conn_ctx->header_list;
        assert(headers);

        if (!_curl_setopt_i(easy, CURLOPT_POST,           1L,              err)
         || !_curl_setopt_p(easy, CURLOPT_HTTPHEADER,     headers,         err)
         || !_curl_setopt_f(easy, CURLOPT_READFUNCTION,   _curl_read_cb,   err)
         || !_curl_setopt_p(easy, CURLOPT_READDATA,       conn,            err)
         || !_curl_setopt_f(easy, CURLOPT_WRITEFUNCTION,  _curl_write_cb,  err)
         || !_curl_setopt_p(easy, CURLOPT_WRITEDATA,      conn,            err)
         || !_curl_setopt_i(easy, CURLOPT_VERBOSE,        1L,              err)
         || !_curl_setopt_f(easy, CURLOPT_DEBUGFUNCTION,  _curl_debug_cb,  err)
         || !_curl_setopt_p(easy, CURLOPT_PRIVATE,        conn,            err)
         || !_curl_setopt_i(easy, CURLOPT_NOPROGRESS,     1L,              err)
         || !_curl_setopt_i(easy, CURLOPT_CONNECTTIMEOUT, CONNECT_TIMEOUT, err)
         || !_curl_setopt_i(easy, CURLOPT_TIMEOUT_MS,     timeout_ms,      err))
        {
            curl_easy_cleanup(easy);
            goto _curl_send_request_fail_label;
        }

        // the call to curl_multi_add_handle() above will set a time-out to
        // trigger very soon so that the necessary socket_action() call will
        // fire
        conn->easy = easy;
    }

    jw_log_dom(JW_LOG_DEBUG, body, "starting request on req_arg=%d: ", req_arg);

    if (!_curl_setopt_p(conn->easy, CURLOPT_URL,           url,     err)
     || !_curl_setopt_i(conn->easy, CURLOPT_POSTFIELDSIZE, req_len, err)
     || !_check_curl_mcode(
            curl_multi_add_handle(conn_ctx->multi, conn->easy), err))
    {
        goto _curl_send_request_fail_label;
    }

    if (conn->req_buf)
    {
        evbuffer_free(conn->req_buf);
    }
    conn->req_buf = body_buf;
    conn->req_arg = req_arg;
    conn->active  = true;

    // start request and update num_active statistic
    _do_multi_socket_action(conn_ctx);

    POP_CONN_NDC;
    return true;

_curl_send_request_fail_label:
    if (body_buf)
    {
        evbuffer_free(body_buf);
    }
    conn_ctx->error_cb(err->code, conn_ctx->cb_arg);
    POP_CONN_NDC;
    return false;
}

#endif
