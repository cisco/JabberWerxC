/**
 * \file
 * \brief
 * Stream typedefs. private, not for use outside library and unit tests.
 *
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

#ifndef JABBERWERX_STREAM_INT_H
#define JABBERWERX_STREAM_INT_H

#include "timer.h"
#include <jabberwerx/util/log.h>
#include <jabberwerx/util/parser.h>
#include <jabberwerx/util/serializer.h>
#include <jabberwerx/util/workq.h>
#include <jabberwerx/stream.h>

#include <event2/event.h>
#include <event2/buffer.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define JW_STREAM_NAMESPACE_PREFIX "stream"
#define JW_STREAM_NAMESPACE_URI "http://etherx.jabber.org/streams"
#define JW_STREAM_ENAME_ERROR "{" JW_STREAM_NAMESPACE_URI "}error"
#define JW_STREAM_ENAME_FEATURES "{" JW_STREAM_NAMESPACE_URI "}features"
#define JW_STREAM_ENAME_STREAM "{" JW_STREAM_NAMESPACE_URI "}stream"

#define JW_STREAM_ATTR_FROM "{}from"
#define JW_STREAM_ATTR_ID "{}id"
#define JW_STREAM_ATTR_TO "{}to"
#define JW_STREAM_ATTR_VERSION "{}version"

#define JW_STREAM_VERSION "1.0"

#define JW_STREAM_ERROR_NAMESPACE "urn:ietf:params:xml:ns:xmpp-streams"
#define JW_STREAM_ERROR_NO_RSRC \
    "{"JW_STREAM_ERROR_NAMESPACE"}resource-constraint"
#define JW_STREAM_ERROR_INT_SERVER \
    "{"JW_STREAM_ERROR_NAMESPACE"}internal-server-error"
#define JW_STREAM_ERROR_SOCK_CONNECT \
    "{"JW_STREAM_ERROR_NAMESPACE"}remote-connection-failed"
#define JW_STREAM_ERROR_REMOTE_CONN_FAILED \
    JW_STREAM_ERROR_SOCK_CONNECT
#define JW_STREAM_ERROR_CONN_TIMEOUT \
    "{"JW_STREAM_ERROR_NAMESPACE"}connection-timeout"
#define JW_STREAM_ERROR_RESET \
    "{"JW_STREAM_ERROR_NAMESPACE"}reset"
#define JW_STREAM_ERROR_POLICY_VIOLATION \
    "{"JW_STREAM_ERROR_NAMESPACE"}policy-violation"
#define JW_STREAM_ERROR_RESOURCE_CONSTRAINT \
    "{"JW_STREAM_ERROR_NAMESPACE"}resource-constraint"
#define JW_STREAM_ERROR_CONFLICT \
    "{"JW_STREAM_ERROR_NAMESPACE"}conflict"
#define JW_STREAM_ERROR_SYSTEM_SHUTDOWN \
    "{"JW_STREAM_ERROR_NAMESPACE"}system-shutdown"
#define JW_STREAM_ERROR_SEE_OTHER_HOST \
    "{"JW_STREAM_ERROR_NAMESPACE"}see-other-host"
#define JW_STREAM_ERROR_NOT_AUTHORIZED \
    "{"JW_STREAM_ERROR_NAMESPACE"}not-authorized"
#define JW_STREAM_ERROR_UNDEFINED_CONDITION \
    "{"JW_STREAM_ERROR_NAMESPACE"}undefined-condition"

#define JW_STREAM_CONFIG_STREAM_ID_ "streamid"

typedef enum
{
    STATE_STREAM_INIT = 0,
    STATE_SOCKET_RESOLVE,
    STATE_SOCKET_CONNECT,
    STATE_SOCKET_STREAM_OUT,
    STATE_SOCKET_STREAM_IN,
    STATE_SOCKET_FEATURES_IN,
    STATE_STREAM_READY,
    STATE_STREAM_CLOSING
} _state_type;

typedef struct _jw_node_queue_int
{
    size_t      size;
    size_t      index;
    jw_dom_node **nodes;
} *_jw_node_queue;

typedef void (*jw_stream_destroy_func)(jw_stream *stream);
typedef bool (*jw_stream_open_func)(jw_stream *stream,
                                    jw_htable *config,
                                    jw_err    *err);
typedef bool (*jw_stream_reopen_func)(jw_stream *stream,
                                      jw_err    *err);
typedef bool (*jw_stream_send_func)(jw_stream   *stream,
                                    jw_dom_node *dom,
                                    jw_err      *err);
typedef void (*jw_stream_close_func)(jw_stream *stream,
                                     jw_errcode close_reason);

typedef struct _jw_stream_function_table_int
{
    jw_stream_destroy_func jw_stream_destroy;
    jw_stream_open_func    jw_stream_open;
    jw_stream_reopen_func  jw_stream_reopen;
    jw_stream_send_func    jw_stream_send;
    jw_stream_close_func   jw_stream_close;

    // socket-only elements that should eventually be moved out of this layer
    // and into the socket layer
    bufferevent_data_cb  read_cb;
    bufferevent_data_cb  write_cb;
    bufferevent_event_cb connect_cb;
} _jw_stream_function_table;

struct _jw_stream
{
    _jw_stream_function_table func_table;

    // used for stream-specific context
    void *data;

    // preallocated structures for orderly shutdown guarantee
    jw_workq_item         *close_event;
    jw_event_trigger_data *close_trigger_data;
    jw_event_trigger_data *destroy_trigger_data;

    jw_htable           *config;
    jw_event_dispatcher *dispatch;
    struct event_base   *base;
    jw_dom_node         *error_dom;
    jw_dom_node         *resource_error_dom;
    _state_type          state;
    bool                 destroy_pending;

    // socket-only element that should eventually be moved out of this layer
    // and into the socket layer
    struct bufferevent *bevent;
};

bool _jw_stream_common_setup(jw_stream *stream, jw_workq *workq, jw_err *err);
void _jw_stream_set_error_node_if_not_set(jw_stream *stream, jw_errcode errcode,
                                          jw_dom_node *app_element);
void _jw_stream_clean_error_dom(jw_stream *stream);
jw_dom_node *_jw_stream_create_error_node(jw_errcode err,
                                         jw_dom_node *app_element);
bool _prepare_for_disconnect(jw_stream *stream,
                             jw_workq_func onCloseCb, jw_err *err);
void _clean_disconnect_data(jw_stream *stream);
void _reset_state_result_cb(jw_event_data evt, bool result, void *arg);
uint32_t _get_keepalive_ms(jw_stream *stream);
const char * _jw_stream_state_to_str(jw_stream *stream);
void _log_evbuffer(jw_loglevel level,
                   struct evbuffer *buffer, const char *preamble);

#ifdef __cplusplus
}
#endif

#endif /* JABBERWERX_STREAM_INT_H */
