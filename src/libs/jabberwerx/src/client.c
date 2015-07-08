/**
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

#include "include/client_int.h"
#include "include/sasl_int.h"
#include "include/stream_int.h"
#include "include/utils.h"

#include <jabberwerx/sasl_factory.h>
#include <jabberwerx/crypto/tls.h>
#include <jabberwerx/util/states.h>
#include <jabberwerx/util/str.h>
#include <jabberwerx/util/log.h>

#include <assert.h>
#include <string.h>
#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>

#define MS_PER_SECOND 1000
#define BITS_PER_BYTE 8

#define JW_CLIENT_DEFAULT_PORT "5222"
#define JW_CLIENT_DEFAULT_SM_ACK_REQUEST_THRESHOLD 5
#define JW_CLIENT_DEFAULT_SM_ACK_REQUEST_THRESHOLD_SECONDS 30

// default reconn base in seconds.milliseconds
#define JW_CLIENT_DEFAULT_RECONNECT_BASE_COUNTDOWN_SEC 10
// maximum reconnect timer countdown value (milliseconds), upper limit of wait
//time, default 600 seconds
#define JW_CLIENT_DEFAULT_RECONNECT_MAX_COUNTDOWN_MS 600000

#define JW_CLIENT_CONFIG_RECONN_JID "jw-client-config-reconn-jid"
// location provided during stream management enabling
#define JW_CLIENT_CONFIG_RECONN_LOCATION "jw-client-config-reconn-location"

#define JW_CLIENT_IQ_LOCALNAME "iq"
#define JW_CLIENT_PRESENCE_LOCALNAME "presence"
#define JW_CLIENT_MESSAGE_LOCALNAME "message"
#define JW_CLIENT_ERROR_LOCALNAME "error"

#define JW_CLIENT_URI "jabber:client"
#define JW_CLIENT_IQ "{" JW_CLIENT_URI "}" JW_CLIENT_IQ_LOCALNAME
#define JW_CLIENT_PRESENCE "{" JW_CLIENT_URI "}" JW_CLIENT_PRESENCE_LOCALNAME
#define JW_CLIENT_MESSAGE "{" JW_CLIENT_URI "}" JW_CLIENT_MESSAGE_LOCALNAME
#define JW_CLIENT_ERROR "{" JW_CLIENT_URI "}" JW_CLIENT_ERROR_LOCALNAME

#define JW_CLIENT_TLS_URI "urn:ietf:params:xml:ns:xmpp-tls"
#define JW_CLIENT_TLS_STARTTLS "{"JW_CLIENT_TLS_URI"}starttls"
#define JW_CLIENT_TLS_REQUIRED "{"JW_CLIENT_TLS_URI"}required"
#define JW_CLIENT_TLS_FAILURE "{"JW_CLIENT_TLS_URI"}failure"
#define JW_CLIENT_TLS_PROCEED "{"JW_CLIENT_TLS_URI"}proceed"

#define JW_CLIENT_SASL_URI "urn:ietf:params:xml:ns:xmpp-sasl"
#define JW_CLIENT_SASL_MECHS "{" JW_CLIENT_SASL_URI "}mechanisms"
#define JW_CLIENT_SASL_AUTH "{" JW_CLIENT_SASL_URI "}auth"
#define JW_CLIENT_SASL_SUCCESS "{" JW_CLIENT_SASL_URI "}success"
#define JW_CLIENT_SASL_FAILURE "{" JW_CLIENT_SASL_URI "}failure"

#define JW_CLIENT_BIND_URI "urn:ietf:params:xml:ns:xmpp-bind"
#define JW_CLIENT_BIND "{" JW_CLIENT_BIND_URI "}bind"
#define JW_CLIENT_BIND_JID "{" JW_CLIENT_BIND_URI "}jid"
#define JW_CLIENT_BIND_RESOURCE "{" JW_CLIENT_BIND_URI "}resource"

#define JW_CLIENT_SM_URI "urn:xmpp:sm:3"
#define JW_CLIENT_SM "{" JW_CLIENT_SM_URI "}sm"
#define JW_CLIENT_SM_ENABLE "{" JW_CLIENT_SM_URI "}enable"
#define JW_CLIENT_SM_ENABLED_LOCALNAME "enabled"
#define JW_CLIENT_SM_ENABLED "{" JW_CLIENT_SM_URI "}" JW_CLIENT_SM_ENABLED_LOCALNAME
#define JW_CLIENT_SM_FAILED_LOCALNAME "failed"
#define JW_CLIENT_SM_FAILED "{" JW_CLIENT_SM_URI "}" JW_CLIENT_SM_FAILED_LOCALNAME
#define JW_CLIENT_SM_A_LOCALNAME "a"
#define JW_CLIENT_SM_REQUIRED_LOCALNAME "required"
#define JW_CLIENT_SM_A "{" JW_CLIENT_SM_URI "}" JW_CLIENT_SM_A_LOCALNAME
#define JW_CLIENT_SM_R_LOCALNAME "r"
#define JW_CLIENT_SM_R "{" JW_CLIENT_SM_URI "}" JW_CLIENT_SM_R_LOCALNAME
#define JW_CLIENT_SM_RESUME_LOCALNAME "resume"
#define JW_CLIENT_SM_RESUME "{"JW_CLIENT_SM_URI"}"JW_CLIENT_SM_RESUME_LOCALNAME
#define JW_CLIENT_SM_RESUMED_LOCALNAME "resumed"
#define JW_CLIENT_SM_RESUMED "{"JW_CLIENT_SM_URI"}"JW_CLIENT_SM_RESUMED_LOCALNAME
#define JW_CLIENT_SM_REQUIRED "{"JW_CLIENT_SM_URI"}"JW_CLIENT_SM_REQUIRED_LOCALNAME

struct _jw_client_status
{
    jw_client_statustype cur_status;
    jw_client_statustype prev_status;
    jw_dom_node    *err_dom;
    bool                 reconnecting;
};

/**
 * Reconnection information including configuration, number of attempts already
 * tried, the countdown to the next attempt (0 if not attempting) and the
 * status of reconnection.
 */
struct _jw_client_reconnect_status
{
    /**
     * cache the config used in the last successful login.
     * Contains reconnect entries for
     *    auth credentials (username and password) user supplied
     *    base countdown optionally user-supplied. value 0 disables reconnect,
     *       if not defined default is used.
     *    last connected jid username@domain/bound-resource|explicit-resource
     *       reconnect added node, value is char* full jid.
     *
     * When starting an attempt, reconn updates USERJID as needed before calling
     * jw_client_connect.
     */
    jw_htable *config;         // configuration from last good connect
    uint32_t  attempts;        // number of attempts made
    uint64_t  countdown;       // number of milliseconds until the next attempt
    jw_workq_item *timer;      // timer to next attempt, NULL if none scheduled
    jw_client_reconnect_statustype status;
};

struct _jw_client
{
    jw_stream                *stream;
    jw_states                *states;
    jw_event_dispatcher      *dispatch;
    struct _jw_client_status       status;
    jw_tls_ctx               *tls_ctx;
    jw_event_trigger_data    *destroy_trigger_data;
    bool                           destroying; // flag true in jw_client_destroy
    jw_jid                   *jid;
    jw_tracker               *tracker;
    jw_workq                 *workq;
    jw_sasl_mech_instance    *mech_instance;

    struct _stream_mgmt_state_int      stream_mgmt_state;
    struct _jw_client_reconnect_status reconn;
};

// client states
enum
{
    INIT = 0,       // initial state after construction
    FEAT_TLS,       // TLS initialization, handshake and completion
    FEAT_SASL,      // SASL negotiation and mechanism evaluation
    FEAT_RESUME,    // A xep-198 session resumption attempt
    FEAT_BIND,      // JID binding, SM handling
    OPENED,         // client is connected and a session established
    CLOSING,        // user requested disconnection
    CLOSED,         // client disconnected, stream does not exist
    PAUSED          // client is waiting for auto-reconnect and
                    // session continuation
};

static const char *CLIENT_STATE_NAMES[] = {
    JW_STATES_NAME(INIT),
    JW_STATES_NAME(FEAT_TLS),
    JW_STATES_NAME(FEAT_SASL),
    JW_STATES_NAME(FEAT_RESUME),
    JW_STATES_NAME(FEAT_BIND),
    JW_STATES_NAME(OPENED),
    JW_STATES_NAME(CLOSING),
    JW_STATES_NAME(CLOSED),
    JW_STATES_NAME(PAUSED),
    NULL
};

/********************************************
 * Internal functions
 *******************************************/

#define PUSH_CLIENT_NDC int _ndcDepth = _push_client_ndc(client, __func__)
#define POP_CLIENT_NDC jw_log_pop_ndc(_ndcDepth)
static int _push_client_ndc(jw_client *client, const char *entrypoint)
{
    assert(client);
    assert(entrypoint);

    char *jid = "";
    jw_htable *config = client->reconn.config;
    if (config)
    {
        char *configJid = jw_htable_get(config, JW_CLIENT_CONFIG_USERJID);
        if (configJid)
        {
            jid = configJid;
        }
    }

    return jw_log_push_ndc("client=%p; jid=%s; entrypoint=%s",
                           (void *)client, jid, entrypoint);
}

static void _set_next_status(struct _jw_client_status *status_data,
                             jw_client_statustype      cur_status)
{
    JW_LOG_TRACE_FUNCTION("cur_status=%d", cur_status);

    status_data->prev_status = status_data->cur_status;
    status_data->cur_status  = cur_status;

    if (status_data->err_dom)
    {
        jw_dom_context_destroy(jw_dom_get_context(status_data->err_dom));
        status_data->err_dom = NULL;
    }
}

static bool _dup_status(
        jw_client_status *status, jw_client_status **ret_status, jw_err *err)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(status);
    assert(ret_status);

    jw_client_status *ret = jw_data_malloc(sizeof(struct _jw_client_status));

    if (NULL == ret)
    {
        jw_log(JW_LOG_WARN, "could not allocate client status");
        JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
        return false;
    }

    ret->cur_status   = status->cur_status;
    ret->prev_status  = status->prev_status;
    ret->reconnecting = status->reconnecting;

    if (status->err_dom)
    {
        if (!jw_dom_context_retain(jw_dom_get_context(status->err_dom), err))
        {
            jw_log_err(JW_LOG_WARN, err,
                       "could not retain client status err dom ctx");
            jw_data_free(ret);
            return false;
        }
    }
    ret->err_dom = status->err_dom;

    *ret_status = ret;
    return true;
}

static void _destroy_status(jw_client_status *status)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(status);

    if (status->err_dom)
    {
        jw_dom_context_destroy(jw_dom_get_context(status->err_dom));
    }

    jw_data_free(status);
}

static void _destroy_status_result_cb(jw_event_data evt,
                                      bool          result,
                                      void         *arg)
{
    UNUSED_PARAM(result);
    UNUSED_PARAM(arg);

    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(evt);
    jw_client_status *status = evt->data;

    _destroy_status(status);
}

// only duplicates fields that are used by getter functions
static bool _dup_reconn_status(
        jw_client_reconnect_status  *status,
        jw_client_reconnect_status **ret_status, jw_err *err)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(status);
    assert(ret_status);

    size_t ret_size = sizeof(struct _jw_client_reconnect_status);
    jw_client_reconnect_status *ret = jw_data_malloc(ret_size);

    if (NULL == ret)
    {
        jw_log(JW_LOG_WARN, "could not allocate client reconnect status");
        JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
        return false;
    }

    memset(ret, 0, ret_size);
    ret->attempts  = status->attempts;
    ret->countdown = status->countdown;
    ret->status    = status->status;

    *ret_status = ret;
    return true;
}

static void _destroy_reconn_status(jw_client_reconnect_status *status)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(status);

    jw_data_free(status);
}

static void _destroy_reconn_status_result_cb(jw_event_data evt,
                                             bool          result,
                                             void         *arg)
{
    UNUSED_PARAM(result);
    UNUSED_PARAM(arg);

    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(evt);
    jw_client_reconnect_status *status = evt->data;

    _destroy_reconn_status(status);
}

static void _destroy_context_result_cb(jw_event_data evt,
                                       bool          result,
                                       void         *arg)
{
    UNUSED_PARAM(result);
    UNUSED_PARAM(arg);

    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(evt);
    jw_dom_node *dom = evt->data;

    if (dom)
    {
        jw_dom_context_destroy(jw_dom_get_context(dom));
    }
}

/**
 * Stream event handlers.
 */
// <stream:features/> handlers for TLS, SASL, bind, xep198
static void _stream_features_tls(jw_event_data event, void *data);
static void _stream_features_sasl(jw_event_data event, void *data);
static void _stream_features_resume(jw_event_data event, void *data);
static void _stream_features_bind(jw_event_data event, void *data);
// inbound stanza event callbacks for featutres
static void _stream_event_recv_tls(jw_event_data event, void *arg);
static void _stream_event_recv_sasl(jw_event_data event, void *arg);
static void _stream_event_recv_resume(jw_event_data event, void *arg);
static void _stream_event_recv_bind(jw_event_data event, void *arg);
// sent and received element handlers when fully connected
static void _stream_event_recv(jw_event_data event, void *data);
static void _stream_event_sent(jw_event_data event, void *data);

static void _stream_event_closed(jw_event_data event, void *data);
static void _stream_destroyed_cb(jw_event_data evt, void *arg);

static void _stream_features_sasl_int(jw_dom_node *node, jw_client *client);
static bool _finish_connect(jw_client *client, bool resuming, jw_err *err);
static void _close_on_error(jw_client *client, jw_err *err);

/**
 * client state helper functions.
 */
/**
 * Destroy the given client's state object, sets client->states to NULL
 */
static void _client_state_finalize(jw_client *client)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    if (client->states)
    {
        jw_states_destroy(client->states);
        client->states = NULL;
    }
}
/**
 * use the given client's workq to create a new jw_states object for the client.
 * return false and sets error if needed. On error client's state will be NULL
 */
static bool _client_state_initialize(jw_client *client,
                                     jw_err         *err)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    if (!jw_states_create(CLIENT_STATE_NAMES,
                          INIT,
                          client->workq,
                          &client->states,
                          err))
    {
        jw_log_err(JW_LOG_WARN, err, "failed to create client states");
        return false;
    }
    return true;
}
/**
 * register the given stream's events with the given states object.
 * Returns true if stream events could be registered with client's states object
 * else returns false.
 *
 * finalizes clients state on error (client->states == NULL)
 */
static bool _client_state_bind_stream(jw_client *client,
                                      jw_stream *stream,
                                      jw_err         *err)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    // initialize states engine
    jw_event  *opened    = jw_stream_event(stream, JW_STREAM_EVENT_OPENED);
    jw_event  *closed    = jw_stream_event(stream, JW_STREAM_EVENT_CLOSED);
    jw_event  *elemrecv  = jw_stream_event(stream, JW_STREAM_EVENT_ELEMRECV);
    jw_event  *elemsent  = jw_stream_event(stream, JW_STREAM_EVENT_ELEMSENT);
    jw_event  *destroyed = jw_stream_event(stream, JW_STREAM_EVENT_DESTROYED);

#define REGISTER(state, evt, cb) \
        jw_states_register_for(client->states, (state), (evt), (cb), client, err)

    if (!REGISTER(FEAT_TLS,  opened,    _stream_features_tls)
     || !REGISTER(FEAT_TLS,  closed,    _stream_event_closed)
     || !REGISTER(FEAT_TLS,  elemrecv,  _stream_event_recv_tls)
     || !REGISTER(FEAT_TLS,  destroyed, _stream_destroyed_cb)
     || !REGISTER(FEAT_SASL, opened,    _stream_features_sasl)
     || !REGISTER(FEAT_SASL, closed,    _stream_event_closed)
     || !REGISTER(FEAT_SASL, elemrecv,  _stream_event_recv_sasl)
     || !REGISTER(FEAT_SASL, destroyed, _stream_destroyed_cb)
     || !REGISTER(FEAT_RESUME, opened,  _stream_features_resume)
     || !REGISTER(FEAT_RESUME, closed,  _stream_event_closed)
     || !REGISTER(FEAT_RESUME, elemrecv,_stream_event_recv_resume)
     || !REGISTER(FEAT_RESUME, destroyed,_stream_destroyed_cb)
     || !REGISTER(FEAT_BIND, opened,    _stream_features_bind)
     || !REGISTER(FEAT_BIND, closed,    _stream_event_closed)
     || !REGISTER(FEAT_BIND, elemrecv,  _stream_event_recv_bind)
     || !REGISTER(FEAT_BIND, destroyed, _stream_destroyed_cb)
     || !REGISTER(OPENED,    elemrecv,  _stream_event_recv)
     || !REGISTER(OPENED,    elemsent,  _stream_event_sent)
     || !REGISTER(OPENED,    closed,    _stream_event_closed)
     || !REGISTER(OPENED,    destroyed, _stream_destroyed_cb)
     || !REGISTER(CLOSING,   elemrecv,  _stream_event_recv)
     || !REGISTER(CLOSING,   closed,    _stream_event_closed)
     || !REGISTER(CLOSING,   destroyed, _stream_destroyed_cb)
     || !REGISTER(CLOSED,    destroyed, _stream_destroyed_cb)
     //jw_client_disconnect while PAUSED
     || !REGISTER(PAUSED,    closed,    _stream_event_closed)
     || !REGISTER(PAUSED,    destroyed, _stream_destroyed_cb))

    {
        jw_log_err(JW_LOG_WARN,
                   err,
                   "failed to register stream events with client states");
        return false;
    }
#undef REGISTER

    return true;
}

static inline bool _client_state_change(jw_client *client,
                                        jw_state_val    next,
                                        jw_err         *err)
{
    jw_log(JW_LOG_DEBUG, "client state changing: '%s' -> '%s'",
           jw_states_get_name_for(client->states,
                                  jw_states_get_current(client->states)),
           jw_states_get_name_for(client->states, next));

    if (!jw_states_change(client->states, next, NULL, NULL, err))
    {
        jw_log_err(JW_LOG_WARN, err, "client state change failed");
        return false;
    }
    return true;
}

static inline bool _client_is_open(jw_client *client)
{
    return jw_states_get_current(client->states) == OPENED;
}

static void _reconn_on_before_disconnect(jw_client *client, jw_dom_node *err);
static const char* _reconn_status_string(jw_client_reconnect_statustype status);

// err is an input variable here -- ensure it is set before calling this fn
static void _close_on_error(jw_client *client, jw_err *err)
{
    assert(client);
    assert(err);

    JW_LOG_TRACE_FUNCTION("err=%d (%s)", err->code, err->message);
    _reconn_on_before_disconnect(client, client->status.err_dom);
    if (err->code == JW_ERR_NO_MEMORY)
    {
        _set_next_status(&client->status, JW_CLIENT_DISCONNECTED);
    }

    // "streamClosed" callback updates client status and error and
    // triggers "clientStatusChanged" and "clientDisconnected",
    // or clientSessionPaused, clientReconnStatusChange
    jw_stream_close(client->stream, err->code);
}

static void _trigger_status_changed(jw_client *client)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    jw_err err;
    jw_event *evt;

    if (client->status.prev_status != client->status.cur_status)
    {
        jw_client_status *new_status;
        if (!_dup_status(&client->status, &new_status, &err))
        {
            _close_on_error(client, &err);
            return;
        }

        evt = jw_client_event(client, JW_CLIENT_EVENT_STATUSCHANGED);
        if (!jw_event_trigger(evt, new_status,
                              _destroy_status_result_cb, NULL, &err))
        {
            jw_log_err(JW_LOG_WARN, &err,
                       "unable to trigger statusChanged event");
            _destroy_status(new_status);
            _close_on_error(client, &err);
            return;
        }

        if (new_status->cur_status == JW_CLIENT_CONNECTED)
        {
            evt = jw_client_event(client, JW_CLIENT_EVENT_CONNECTED);
            if (!jw_event_trigger(evt, NULL, NULL, NULL, &err))
            {
                jw_log_err(JW_LOG_WARN, &err,
                           "unable to trigger connected event");
                _close_on_error(client, &err);
            }
        }
        else if (new_status->cur_status == JW_CLIENT_DISCONNECTED)
        {
            if (new_status->err_dom)
            {
                if (!jw_dom_context_retain(
                        jw_dom_get_context(new_status->err_dom), &err))
                {
                    jw_log(JW_LOG_WARN,
                           "could not retain client status err dom ctx");
                    _close_on_error(client, &err);
                    return;
                }
            }

            evt = jw_client_event(client, JW_CLIENT_EVENT_DISCONNECTED);
            if (!jw_event_trigger(evt, new_status->err_dom,
                                  _destroy_context_result_cb, NULL, &err))
            {
                jw_log_err(JW_LOG_WARN, &err,
                           "unable to trigger disconnected event");
                _close_on_error(client, &err);
            }
        }
    }
}

static void _trigger_reconnect_changed(jw_client *client,
                                       jw_client_reconnect_statustype next)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    jw_err err;
    if (next != client->reconn.status)
    {
        jw_log(JW_LOG_DEBUG,
               "_trigger_reconnect_changed %s -> %s",
               _reconn_status_string(client->reconn.status),
               _reconn_status_string(next));
        client->reconn.status = next;

        jw_client_reconnect_status *new_status = NULL;
        if (!_dup_reconn_status(&client->reconn, &new_status, &err)
         || !jw_event_trigger(jw_client_event(
                                       client,
                                       JW_CLIENT_EVENT_RECONNECT_STATUSCHANGED),
                              new_status, _destroy_reconn_status_result_cb,
                              NULL, &err))
        {
            jw_log_err(JW_LOG_WARN, &err,
                       "unable to trigger reconnectStatusChanged event");
            _destroy_reconn_status(new_status);

            // don't close stream if disconnected
            if (jw_client_is_connected(client))
            {
                _close_on_error(client, &err);
            }
        }
    }
}

/**
 * Create a new jid from the given client's configuration or string. If jid_str
 * is NULL JW_CLIENT_CONFIG_USERJID is used. return NULL on error;
 */
static jw_jid *_new_jid(jw_htable *config, const char *jid_str, jw_err *err)
{
    JW_LOG_TRACE_FUNCTION("jid_str='%s'", jid_str);

    jw_jid_ctx *jidCtx = jw_htable_get(config, JW_CLIENT_CONFIG_JID_CONTEXT);

    if (!jidCtx && (!jw_jid_context_create(0, &jidCtx, err) ||
                    !jw_htable_put(config,
                                   JW_CLIENT_CONFIG_JID_CONTEXT,
                                   jidCtx,
                                   jw_jid_context_htable_cleaner,
                                   err)))
    {
        // clean up successful create but failed put
        if (jidCtx)
        {
            jw_jid_context_destroy(jidCtx);
        }
        else
        {
            jw_log(JW_LOG_WARN, "could not create jid context for client");
        }
        return NULL;
    }

    jw_jid      *ret;
    const char *jidstr = jid_str;
    if (!jidstr)
    {
       jidstr = jw_htable_get(config, JW_CLIENT_CONFIG_USERJID);
    }
    if (!jw_jid_create(jidCtx, jidstr, &ret, err))
    {
        return NULL;
    }
    return ret;
}

static bool _unacked_stanza_node_push(
        _stream_mgmt_state sm_state,
        jw_dom_node *stanza,
        jw_err *err)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(sm_state);

    if (!jw_dom_context_retain(jw_dom_get_context(stanza), err))
    {
        return false;
    }

    _stanza_queue node = jw_data_malloc(sizeof(struct _stanza_queue_int));
    if (NULL == node)
    {
        JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
        jw_log_err(JW_LOG_WARN, err,
                   "cannot allocate unacked stanza queue node");
        jw_dom_context_destroy(jw_dom_get_context(stanza));
        return false;
    }
    jw_log(JW_LOG_TRACE, "allocating stanza node %p", (void *)node);

    node->stanza = stanza;
    node->next = NULL;

    if (NULL == sm_state->unacked_stanzas_tail)
    {
        assert(0 == sm_state->num_unacked_stanzas);
        sm_state->unacked_stanzas = node;
    }
    else
    {
        assert(0 != sm_state->num_unacked_stanzas);
        sm_state->unacked_stanzas_tail->next = node;
    }
    sm_state->unacked_stanzas_tail = node;

    return true;
}

// updates cur_node pointer to next node
static void _unacked_stanza_node_pop(_stanza_queue *cur_node)
{
    assert(cur_node);
    assert(*cur_node);

    jw_log(JW_LOG_TRACE, "freeing stanza node %p", (void *)*cur_node);
    jw_dom_context_destroy(jw_dom_get_context((*cur_node)->stanza));
    _stanza_queue prev_node = *cur_node;
    *cur_node = (*cur_node)->next;
    jw_data_free(prev_node);
}

static void _clean_stream_mgmt_state(_stream_mgmt_state stream_mgmt_state)
{
    jw_data_free(stream_mgmt_state->resume_id);
    jw_data_free(stream_mgmt_state->resume_location);

    if (stream_mgmt_state->ack_request_timer)
    {
        jw_timer_destroy(stream_mgmt_state->ack_request_timer);
    }

    _stanza_queue cur_node = stream_mgmt_state->unacked_stanzas;
    while (NULL != cur_node)
    {
        _unacked_stanza_node_pop(&cur_node);
    }

    memset(stream_mgmt_state, 0, sizeof(struct _stream_mgmt_state_int));
}


/*******************************************************************
 * startTLS functions. Boilerplate cries out for pluggable features
 ******************************************************************/
/* Find <starttls/> as a child of features,
   set required flag based on elements */
static bool _find_starttls(jw_dom_node *features, bool *is_required)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    jw_dom_node *starttls;

    *is_required = false;
    if (features)
    {
        starttls = jw_dom_get_first_element(features, JW_CLIENT_TLS_STARTTLS);
        if (starttls)
        {
            /* rfc 6120 5.3.1
              TLS required if <required/> is a child of <starttls/> or
              <starttls/> is the only child of <stream:features/> */
            *is_required =
               (jw_dom_get_first_element(starttls,JW_CLIENT_TLS_REQUIRED)!=NULL)
                || ((jw_dom_get_first_child(features) == starttls)
                     && (jw_dom_get_sibling(starttls) == NULL));
            return true;
        }
    }
    return false;
}

/**
 * listen for result of sending <starttls/>. Either failure or proceed.
 * Move state to SASL on success, else close with error
 */
static void _stream_event_recv_tls(jw_event_data event, void *arg)
{
    jw_stream    *stream = event->source;
    jw_dom_node **response = event->data;
    jw_client    *client = arg;
    jw_err             err;

    PUSH_CLIENT_NDC;
    JW_LOG_TRACE_FUNCTION_NO_ARGS;
    if (!response || response[1])
    {
        jw_log(JW_LOG_WARN, "received bad protocol during TLS negotiation");
        JABBERWERX_ERROR(&err, JW_ERR_PROTOCOL);
        _close_on_error(client, &err);
    }
    else if (jw_strcmp(jw_dom_get_ename(response[0]), JW_CLIENT_TLS_PROCEED) != 0)
    {
        jw_log_dom(JW_LOG_WARN,
                   response[0],
                   "Did not receive proceed during TLS negotiation: ");
        JABBERWERX_ERROR(&err, JW_ERR_PROTOCOL);
        _close_on_error(client, &err);
    }
    else if (!jw_tls_filter_stream(client->tls_ctx, stream, NULL, &err))
    {
        jw_log(JW_LOG_WARN, "Could not attach TLS filter to stream");
        _close_on_error(client, &err);
    }
    else if (!_client_state_change(client, FEAT_SASL, &err))
    {
        jw_log(JW_LOG_WARN, "Could not change client state to SASL.");
        _close_on_error(client, &err);
    }
    else if (!jw_stream_reopen(stream, &err))
    {
        jw_log(JW_LOG_WARN, "Could not reopen stream after TLS negotiation");
        _close_on_error(client, &err);
    }

    POP_CLIENT_NDC;
}

/**
 * check and configure starttls.
 */
static void _stream_features_tls(jw_event_data event, void *arg)
{
    jw_client *client = arg;
    PUSH_CLIENT_NDC;
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    jw_htable *config      = jw_client_get_config(client);
    bool            required    = false;
    bool            found_start = false;
    jw_err          err;

    jw_log(JW_LOG_INFO, "stream opened");
    jw_log_dom(JW_LOG_DEBUG, event->data, "handling starttls feature");

    found_start = _find_starttls(event->data, &required);
    // rfc6120 5.3.1.  Mandatory-to-Negotiate MUST use TLS if required
    // and SHOULD use if available
    // TLS is implemented and in features, required or not

    // Initialize SSL library and tls context if this is the first request
    if ((!client->tls_ctx && found_start) &&
        (!jw_tls_initialize(&err) ||
         !jw_tls_context_create(&client->tls_ctx, &err)))
    {
        jw_log_err(JW_LOG_WARN, &err, "ssl library initialization failed");
        goto _stream_features_tls_fail_label;
    }

    if (client->tls_ctx && found_start)
    {
        const char *cert_file = (const char *)jw_htable_get(
                       config, JW_STREAM_CONFIG_TLS_CERTIFICATE_CHAIN_FILENAME);
        const char *private_key_file = (const char *)jw_htable_get(
                       config, JW_STREAM_CONFIG_TLS_PRIVATE_KEY_FILENAME);
        if (cert_file && private_key_file)
        {
            jw_log(JW_LOG_DEBUG,
                   "configuring tls context with cert chain from '%s' and"
                   " private key from '%s'", cert_file, private_key_file);
            if (!jw_tls_use_cert_chain(
                        client->tls_ctx, cert_file, private_key_file, &err))
            {
                jw_log(JW_LOG_WARN, "failed to load client certs");
                goto _stream_features_tls_fail_label;
            }
        }
        else if (cert_file || private_key_file)
        {
            jw_log(JW_LOG_WARN,
                   "JW_STREAM_CONFIG_TLS_CERTIFICATE_CHAIN_FILENAME (%s)"
                   " and JW_STREAM_CONFIG_TLS_PRIVATE_KEY_FILENAME (%s)"
                   " must both be set for client certificate auth",
                   cert_file, private_key_file);
        }

        jw_dom_ctx  *dctx;
        jw_dom_node *starttls;

        if (!jw_dom_context_create(&dctx, &err))
        {
            jw_log_err(JW_LOG_WARN, &err,
                       "could not create TLS stanza context");
            goto _stream_features_tls_fail_label;
        }
        if (!jw_dom_element_create(
                        dctx, JW_CLIENT_TLS_STARTTLS, &starttls, &err))
        {
            jw_dom_context_destroy(dctx);
            jw_log_err(JW_LOG_WARN, &err, "could not create TLS stanza");
            goto _stream_features_tls_fail_label;
        }
        if (!jw_stream_send(client->stream, starttls, &err))
        {
            jw_log_err(JW_LOG_WARN, &err, "could not send <starttls/>");
            goto _stream_features_tls_fail_label;
        }
    }
    // tls is not implemented but is required by server or config
    else if (!client->tls_ctx
             && ((found_start && required)
                 || (bool)((uintptr_t)jw_htable_get(config,
                                                    JW_TLS_CONFIG_REQUIRED))))
    {
        jw_log(JW_LOG_WARN, "starttls is mandatory but not available");
        goto _stream_features_tls_fail_label;
    }
    // tls not required and not available (not implemented or not in features)
    //move to FEAT_SASL and forward this packet to SASL's opened handler
    else
    {
        jw_log(JW_LOG_DEBUG,
               "TLS is not required and not available, skipping to SASL");
        if (!_client_state_change(client, FEAT_SASL, &err))
        {
            goto _stream_features_tls_fail_label;
        }

        _stream_features_sasl_int(event->data, client);
    }

    POP_CLIENT_NDC;
    return;
_stream_features_tls_fail_label:
    _close_on_error(client, &err);
}


/********************************************
 * Authentication functions
 *******************************************/
static void _sasl_mech_evaluate_complete(
                        jw_sasl_mech_instance *instance,
                        jw_dom_node           *out_auth_node,
                        bool                  done,
                        jw_sasl_error         sasl_err,
                        void                 *arg)
{
    JW_LOG_TRACE_FUNCTION("sasl_err=%d", sasl_err);

    jw_err    err;
    jw_client *client = arg;

    assert(client);

    if (done || JW_SASL_ERR_NONE != sasl_err)
    {
        const char * mech_name =
                jw_sasl_mech_get_name(jw_sasl_mech_instance_get_mech(instance));
        if (JW_SASL_ERR_NONE != sasl_err)
        {
            jw_log_dom(JW_LOG_INFO, out_auth_node,
                       "could not complete sasl %s auth (sasl_err=%d): ",
                       mech_name, sasl_err);
            JABBERWERX_ERROR(&err, JW_ERR_NOT_AUTHORIZED);

            _jw_stream_set_error_node_if_not_set(
                    client->stream, err.code, out_auth_node);
            goto _sasl_mech_evaluate_complete_fail_label;
        }

        jw_log(JW_LOG_INFO, "authenticated successfully (sasl mechanism: %s)",
               mech_name);

        jw_sasl_mech_instance_destroy(client->mech_instance);
        client->mech_instance = NULL;

        //advance to the FEAT_RESUME state, RESUME attempted on new stream.
        if (!_client_state_change(client, FEAT_RESUME, &err))
        {
            jw_log_err(JW_LOG_WARN, &err, "could not move to FEAT_RESUME state");
            goto _sasl_mech_evaluate_complete_fail_label;
        }

        if (!jw_stream_reopen(client->stream, &err))
        {
            jw_log_err(JW_LOG_WARN, &err, "could not re-open stream");
            goto _sasl_mech_evaluate_complete_fail_label;
        }

        return;
    }

    if (!out_auth_node)
    {
        jw_log(JW_LOG_ERROR, "unexpected NULL node from mechanism");
        assert(false);
    }

    jw_dom_ctx *out_ctx = jw_dom_get_context(out_auth_node);

    if (!jw_dom_context_retain(out_ctx, &err))
    {
        jw_log_err(JW_LOG_WARN, &err, "could not retain sasl auth dom");
        goto _sasl_mech_evaluate_complete_fail_label;
    }

    if (!jw_stream_send(client->stream, out_auth_node, &err))
    {
        jw_log_err(JW_LOG_WARN, &err, "could not send sasl auth dom");
        goto _sasl_mech_evaluate_complete_fail_label;
    }

    return;

_sasl_mech_evaluate_complete_fail_label:

    _close_on_error(client, &err);
}

static void _stream_event_recv_sasl(jw_event_data event, void *arg)
{
    jw_client *client = arg;
    jw_err          err;

    PUSH_CLIENT_NDC;
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(event);
    assert(arg);

    jw_dom_node **received_stanzas = event->data;
    assert(received_stanzas);

    if ((NULL == received_stanzas[0]) || (NULL != received_stanzas[1]))
    {
        jw_log(JW_LOG_WARN, "received bad protocol during SASL attempt");
        JABBERWERX_ERROR(&err, JW_ERR_PROTOCOL);
        _close_on_error(client, &err);
    }
    else if (!jw_sasl_mech_instance_evaluate(
                   client->mech_instance, received_stanzas[0],
                    _sasl_mech_evaluate_complete, client, &err))
    {
        jw_log_err(JW_LOG_WARN, &err, "failed to evaluate sasl element");
        _close_on_error(client, &err);
    }

    POP_CLIENT_NDC;
}

/********************************************
 * Stream management functions
 *******************************************/
static bool _is_sm_enabled(jw_client *client)
{
    assert(client);
    return (0 != (SM_ENABLED & client->stream_mgmt_state.flags));
}

static bool _create_sm(jw_client *client, jw_dom_node **ret_node, jw_err *err)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    jw_dom_ctx *domCtx;
    jw_dom_node *smDom = NULL;
    jw_htable *config = jw_client_get_config(client);

    jw_hnode *sm_node = jw_htable_get_node(config, JW_CLIENT_CONFIG_SM_ENABLED);
    if (!sm_node || (bool)(uintptr_t)jw_hnode_get_value(sm_node))
    {
        if (!jw_dom_context_create(&domCtx, err))
        {
            return false;
        }

        if (!jw_dom_element_create(domCtx, JW_CLIENT_SM_ENABLE, &smDom, err))
        {
            goto _create_sm_fail_label;
        }

        jw_hnode *resume_node =
                jw_htable_get_node(config, JW_CLIENT_CONFIG_SM_RESUME_ENABLED);
        if (!resume_node || (bool)(uintptr_t)jw_hnode_get_value(resume_node))
        {
            if (!jw_dom_set_attribute(smDom, "{}resume", "true", err))
            {
                goto _create_sm_fail_label;
            }
        }

        char *resume_timeout =
                    jw_htable_get(config,
                                  JW_CLIENT_CONFIG_SM_RESUME_TIMEOUT_SECONDS);
        if (resume_timeout)
        {
            // let the server check the validity of the value
            if (!jw_dom_set_attribute(smDom, "{}max", resume_timeout, err))
            {
                goto _create_sm_fail_label;
            }
        }
    }
    else if (0 != (client->stream_mgmt_state.flags & SM_REQUIRED))
    {
        jw_log(JW_LOG_WARN, "server requires stream management,"
                            " but client configuration prohibits it");
        JABBERWERX_ERROR(err, JW_ERR_PROTOCOL);
        return false;
    }

    *ret_node = smDom;
    return true;

_create_sm_fail_label:
    jw_dom_context_destroy(domCtx);
    return false;
}

static bool _do_sm(jw_client *client, jw_err *err)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    jw_stream *stream = client->stream;

    jw_dom_node *sendNode = NULL;
    if (!_create_sm(client, &sendNode, err))
    {
        return false;
    }

    if (!sendNode)
    {
        jw_log(JW_LOG_DEBUG, "stream management not enabled by user choice");
        return true;
    }

    if (!jw_stream_send(stream, sendNode, err))
    {
        jw_log_err(JW_LOG_WARN, err, "could not send stream management dom");
        return false;
    }

    // initialize last ack request timestamp
    jw_timer_mark_activity(client->stream_mgmt_state.ack_request_timer);

    return true;
}

static bool _do_sm_r(jw_client *client, jw_err *err)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    jw_dom_ctx *domCtx;
    jw_dom_node *smRDom = NULL;

    if (!_client_is_open(client))
    {
        return true; // nothing to do, no stream
    }

    if (!jw_dom_context_create(&domCtx, err))
    {
        return false;
    }

    if (!jw_dom_element_create(domCtx, JW_CLIENT_SM_R, &smRDom, err))
    {
        jw_dom_context_destroy(domCtx);
        return false;
    }

    if (!jw_stream_send(client->stream, smRDom, err))
    {
        // do not destroy the stanza -- jw_stream_send will do that
        jw_log_err(JW_LOG_WARN, err,
                   "could not send stream management ack request");
        return false;
    }

    // update our "last request" timestamp
    jw_timer_mark_activity(client->stream_mgmt_state.ack_request_timer);

    return true;
}

// set force to true if client just received an ack from the server and is
// checking to see if another request should be sent immediately
static bool _do_sm_r_if_required(
        jw_client *client, bool force, jw_err *err)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    if (!_is_sm_enabled(client) || !_client_is_open(client))
    {
        // stream management not currently enabled; nothing to do here
        return true;
    }

    _stream_mgmt_state sm_state = &client->stream_mgmt_state;
    uint32_t unacked_stanzas    = sm_state->num_unacked_stanzas;
    uint32_t request_threshold  = sm_state->ack_request_threshold;

    if (request_threshold > unacked_stanzas)
    {
        jw_log(JW_LOG_DEBUG, "ack request threshold not yet reached"
               " (%u < %u); not sending ack request",
               unacked_stanzas, request_threshold);
        return true;
    }

    if (request_threshold == unacked_stanzas)
    {
        jw_log(JW_LOG_DEBUG,
               "reached ack request threshold (%u == %u); sending ack request",
               unacked_stanzas, request_threshold);
    }
    else // request_threshold < unacked_stanzas
    {
        if (!force)
        {
            jw_log(JW_LOG_DEBUG, "passed ack request threshold (%u > %u), but"
                   " request has been recently sent; not sending ack request",
                   unacked_stanzas, request_threshold);
            return true;
        }

        jw_log(JW_LOG_DEBUG, "ack request threshold already passed since last"
               " server update (%u > %u); sending ack request",
               unacked_stanzas, request_threshold);
    }

    jw_log(JW_LOG_DEBUG,
           "beyond ack request threshold (%u >= %u) and request has not been"
           " recently sent; sending ack request",
           unacked_stanzas, request_threshold);

    return _do_sm_r(client, err);
}

static void _timeout_error_handler(jw_event_data event, void *data)
{
    UNUSED_PARAM(event);
    jw_client *client = data;
    assert(client);

    PUSH_CLIENT_NDC;
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    jw_err err = { .code = JW_ERR_NONE };
    _close_on_error(client, &err);

    POP_CLIENT_NDC;
}

static void _sm_r_timeout_handler(jw_event_data event, void *data)
{
    UNUSED_PARAM(event);
    jw_client *client = data;
    assert(client);

    PUSH_CLIENT_NDC;
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    jw_err             err;
    _stream_mgmt_state sm_state = &client->stream_mgmt_state;

    // if there are no unacked stanzas, do nothing
    if (0 == sm_state->num_unacked_stanzas)
    {
        jw_log(JW_LOG_DEBUG, "no unacked stanzas; timeout handler exiting");
    }
    else if (!_do_sm_r(client, &err))
    {
        _close_on_error(client, &err);
    }

    POP_CLIENT_NDC;
}

static bool _do_sm_a(jw_client *client, jw_err *err)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    jw_stream *stream = client->stream;

    jw_dom_ctx *domCtx;
    jw_dom_node *smADom = NULL;

    if (!jw_dom_context_create(&domCtx, err))
    {
        return false;
    }

    if (!jw_dom_element_create(domCtx, JW_CLIENT_SM_A, &smADom, err))
    {
        goto _create_sm_a_fail_label;
    }

    // stringify client "h" value
    jw_pool *pool = jw_dom_context_get_pool(domCtx);
    char *h = NULL;
    if (!jw_pool_malloc(pool, UINT32_MAX_WIDTH, (void **)&h, err))
    {
        goto _create_sm_a_fail_label;
    }
    int result = snprintf(h, UINT32_MAX_WIDTH, "%u",
                          client->stream_mgmt_state.num_received_stanzas);
    if (0 > result || UINT32_MAX_WIDTH <= (uint32_t)result)
    {
        goto _create_sm_a_fail_label;
    }

    if (!jw_dom_set_attribute(smADom, "{}h", h, err))
    {
        goto _create_sm_a_fail_label;
    }

    if (!jw_stream_send(stream, smADom, err))
    {
        // do not destroy the stanza -- jw_stream_send will do that
        jw_log_err(JW_LOG_WARN, err, "could not send stream management ack");
        return false;
    }

    return true;

_create_sm_a_fail_label:
    jw_dom_context_destroy(domCtx);
    return false;
}

static bool _handle_sm_a(jw_client *client, jw_dom_node *node, jw_err *err)
{
    const char *h = jw_dom_get_attribute(node, "h");
    if (!h)
    {
        jw_log(JW_LOG_WARN, "invalid 'a' elem (lacks 'h' attribute)");
        JABBERWERX_ERROR(err, JW_ERR_PROTOCOL);
        return false;
    }

    jw_log(JW_LOG_DEBUG, "receiving sm ack with h=%s", h);

    char *pEnd;
    errno = 0;
    uint32_t server_h = strtoul(h, &pEnd, 10);

    if (errno || '\0' != *pEnd)
    {
        jw_log(JW_LOG_WARN, "cannot parse h attribute: '%s': %s",
               h, strerror(errno));
        JABBERWERX_ERROR(err, JW_ERR_PROTOCOL);
        return false;
    }

    _stream_mgmt_state stream_mgmt_state = &client->stream_mgmt_state;

    // since all variables here are uint32_t, wraparound (i.e. when
    // h grows past UINT32_MAX) is handled correctly and the
    // stream_mgmt_state variables will end up with the correct values.
    uint32_t diff = server_h - stream_mgmt_state->num_server_acked_stanzas;

    _stanza_queue cur_node = stream_mgmt_state->unacked_stanzas;
    uint32_t unacked_stanzas = stream_mgmt_state->num_unacked_stanzas;
    for (uint32_t num = unacked_stanzas; unacked_stanzas - diff != num; --num)
    {
        _unacked_stanza_node_pop(&cur_node);
    }

    stream_mgmt_state->num_unacked_stanzas -= diff;
    stream_mgmt_state->unacked_stanzas = cur_node;
    if (NULL == cur_node)
    {
        stream_mgmt_state->unacked_stanzas_tail = NULL;
    }
    assert((NULL == cur_node && 0 == stream_mgmt_state->num_unacked_stanzas)
        || (NULL != cur_node && 0 != stream_mgmt_state->num_unacked_stanzas));

    stream_mgmt_state->num_server_acked_stanzas = server_h;

    jw_log(JW_LOG_DEBUG,
           "server acked %u new stanza(s); num_unacked_stanzas=%u",
           diff, stream_mgmt_state->num_unacked_stanzas);

    if (!_do_sm_r_if_required(client, true, err))
    {
        jw_log(JW_LOG_WARN, "failed to send ack request");
        return false;
    }

    return true;
}

static bool _send_tracked_stanza(jw_client *client,
                                 jw_dom_node *stanza,
                                 bool push_unacked_stanza,
                                 jw_err *err)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    _stream_mgmt_state sm_state = &client->stream_mgmt_state;

    // if not fully opened simply enqueue the packet
    bool notOpen = !_client_is_open(client);
    if (notOpen || push_unacked_stanza)
    {
        if (!_unacked_stanza_node_push(sm_state, stanza, err))
        {
            return false;
        }
        ++sm_state->num_unacked_stanzas;
        if (notOpen)
        {
            return true;
        }
    }
    
    // otherwise send and track ack
    if (!jw_stream_send(client->stream, stanza, err))
    {
        jw_log(JW_LOG_WARN, "failed to send stanza");
        return false;
    }

    if (!_do_sm_r_if_required(client, false, err))
    {
        jw_log(JW_LOG_WARN, "cannot send ack request");
        return false;
    }

    if (_is_sm_enabled(client))
    {
        jw_timer_mark_activity(sm_state->ack_request_timer);
    }

    return true;
}

/********************************************
 * SM Resume functions
 *******************************************/

// check resume state to make for resume flag
static inline bool _sm_should_resume(jw_client *client)
{
    return (0 != (_jw_client_get_stream_mgmt_state(client)->flags
                  & SM_RESUME_ENABLED));
}

// Called before reconnect is attempted, sets SM preferred location, port
static inline bool _sm_resume_set_config(jw_client *client, jw_err *err)
{
    UNUSED_PARAM(err);

    if (_sm_should_resume(client) &&
        _jw_client_get_stream_mgmt_state(client)->resume_location)
    {
        //todo new location, set config host and port
        jw_log(JW_LOG_DEBUG,
               "Resume at location: %s",
               _jw_client_get_stream_mgmt_state(client)->resume_location);
        jw_log(JW_LOG_WARN,
               "Resumption at a specified location is not supported");
    }

    return true;
}

// Send the sm resume stanza (in lieu of bind)
static bool _sm_do_resume(jw_client *client, jw_err *err)
{
    jw_dom_ctx *ctx;
    jw_dom_node *resume;

    if (_sm_should_resume(client))
    {
        if (!_jw_client_get_stream_mgmt_state(client)->resume_id)
        {
            jw_log(JW_LOG_WARN,
                   "attempted stream management resume without id");
            JABBERWERX_ERROR(err, JW_ERR_PROTOCOL);
            return false;
        }
        if (!_sm_resume_set_config(client, err))
        {
            jw_log_err(JW_LOG_WARN,
                       err,
                       "failed to create set resume configuration");
            return false;
        }
        if (!jw_dom_context_create(&ctx, err))
        {
            jw_log_err(JW_LOG_WARN,
                       err,
                       "failed to create resume stanza context");
            return false;
        }
        jw_pool *pool = jw_dom_context_get_pool(ctx);
        char *h = NULL;
        if (!jw_pool_malloc(pool, UINT32_MAX_WIDTH, (void **)&h, err))
        {
            jw_log_err(JW_LOG_WARN,
                       err,
                       "failed to allocate log string from context pool");
            jw_dom_context_destroy(ctx);
            JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
            return false;
        }
        int result = snprintf(h, UINT32_MAX_WIDTH, "%u",
                             client->stream_mgmt_state.num_received_stanzas);
        if (0 > result || UINT32_MAX_WIDTH <= (uint32_t)result)
        {
            jw_log_err(JW_LOG_WARN,
                       err,
                       "failed to convert received stanza count to string");
            jw_dom_context_destroy(ctx);
            JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
            return false;
        }

        //<resume xmlns='urn:xmpp:sm:3'  h='server count' previd='sm-id'/>
        if (!jw_dom_element_create(ctx, JW_CLIENT_SM_RESUME, &resume, err) ||
            !jw_dom_set_attribute(resume,
                                  "{}previd",
                                  client->stream_mgmt_state.resume_id,
                                  err) ||
            !jw_dom_set_attribute(resume, "{}h",  h, err))
        {
            jw_log_err(JW_LOG_WARN, err, "failed to create resume stanza");
            jw_dom_context_destroy(ctx);
            return false;
        }
        if (!jw_stream_send(client->stream, resume, err))
        {
            jw_log_err(JW_LOG_WARN, err, "failed to send resume stanza");
            return false;
        }
    }

    return true;
}

/********************************************
 * Reconnect functions
 *******************************************/
static void _reconn_on_execute(jw_workq_item *item, void *data);

static inline uint32_t _reconn_base_countdown(jw_client *client)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;
    jw_htable *cfg = client->reconn.config;
    double dtime;
    jw_err err;

    if (!jw_utils_config_get_double(
            cfg,
            JW_CLIENT_CONFIG_RECONNECT_BASE_COUNTDOWN,
            JW_CLIENT_DEFAULT_RECONNECT_BASE_COUNTDOWN_SEC,
            &dtime,
            &err))
    {
        jw_log_err(JW_LOG_WARN,
                   &err,
                   "Could not get JW_CLIENT_CONFIG_RECONNECT_BASE_COUNTDOWN");
        dtime = JW_CLIENT_DEFAULT_RECONNECT_BASE_COUNTDOWN_SEC;
    }

    return jw_utils_dtoms(dtime);
}

static inline jw_client_reconnect_statustype _reconn_status(jw_client *client)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;
    return client->reconn.status;
}
static const char* _reconn_status_string(jw_client_reconnect_statustype status)
{
    switch (status)
    {
        case JW_CLIENT_RECONNECT_CANCELED: return "JW_CLIENT_RECONNECT_CANCELED";
        case JW_CLIENT_RECONNECT_PENDING:  return "JW_CLIENT_RECONNECT_PENDING";
        case JW_CLIENT_RECONNECT_STARTING: return "JW_CLIENT_RECONNECT_STARTING";
    }
    return "JW_CLIENT_RECONNECT_UNKNOWN";
}
static inline bool _reconn_reconnecting(jw_client *client)
{
    return JW_CLIENT_RECONNECT_STARTING == _reconn_status(client);
}
static inline bool _reconn_enabled(jw_client *client)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;
    return 0 != _reconn_base_countdown(client);
}

static bool _reconn_set_jid(jw_client *client, jw_jid *jid, jw_err *err)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    jw_htable *config = jw_client_get_config(client);
    if (config)
    {
        char *jid_str = NULL;
        if (jid)
        {
            jid_str = jw_data_strdup(jw_jid_get_full(jid));
            if (!jid_str)
            {
                JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY)
                return false;
            }
        }
        if (!jw_htable_put(config,
                          JW_CLIENT_CONFIG_RECONN_JID,
                          jid_str,
                          jid_str ? jw_htable_free_data_cleaner : NULL,
                          NULL))
        {
            jw_log(JW_LOG_ERROR, "Could not set pre-allocated htable node");
            assert(false);
        }
    }
    return true;
}

static inline void _reconn_cancel_timer(jw_client *client)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;
    // cancel work queue item
    if (NULL != client->reconn.timer)
    {
        jw_workq_item_destroy(client->reconn.timer);
        client->reconn.timer = NULL;
    }
}
static void _reconn_cancel(jw_client *client)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;
    _reconn_cancel_timer(client);

    // change status and event
    client->reconn.countdown = client->reconn.attempts = 0;
    _reconn_set_jid(client, NULL, NULL);
    client->reconn.config = NULL;

    _trigger_reconnect_changed(client, JW_CLIENT_RECONNECT_CANCELED);
}

static void _reconn_start(jw_client *client)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;
    jw_htable *config = client->reconn.config;
    jw_err err;
    jw_jid *user_jid, *last_jid = NULL, *res_jid = NULL;

    assert(config); //called before first successful login

    user_jid = _new_jid(config, NULL, &err);
    if (!user_jid)
    {
        goto _create_jid_fail_label;
    }

    //Make sure userjid has the last connected JID's resource (if it exists)
    const char* reconn_jidstr = jw_htable_get(config,
                                              JW_CLIENT_CONFIG_RECONN_JID);
    if (reconn_jidstr)
    {
        last_jid = _new_jid(config, reconn_jidstr, &err);
        if (!last_jid)
        {
            goto _create_jid_fail_label;
        }
    }
    if (!jw_jid_create_by_parts(jw_jid_get_context(user_jid),
                                jw_jid_get_localpart(user_jid),
                                jw_jid_get_domain(user_jid),
                                last_jid ? jw_jid_get_resource(last_jid) : "",
                                &res_jid, &err) ||
        !_reconn_set_jid(client, res_jid, &err))
    {
        goto _create_jid_fail_label;
    }

    _trigger_reconnect_changed(client, JW_CLIENT_RECONNECT_STARTING);

    jw_log(JW_LOG_DEBUG,
           "Starting reconnection attempt #%u.",
           client->reconn.attempts);
    // connection attempt will take care of reconnect state
    if (jw_client_connect(client, config, &err))
    {
        goto _cleanup_jids_label;
    }

_create_jid_fail_label:
    jw_log_err(JW_LOG_WARN, &err, "Reconnection failed: ");
    _reconn_cancel(client);

_cleanup_jids_label:
    if (user_jid)
    {
        jw_jid_destroy(user_jid);
    }
    if (last_jid)
    {
        jw_jid_destroy(last_jid);
    }
    if (res_jid)
    {
        jw_jid_destroy(res_jid);
    }
}

static void _reconn_pending(jw_client *client)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;
    jw_err        err;

    assert(client);

    if (_reconn_enabled(client) &&
        NULL != client->reconn.config &&
        NULL == client->reconn.timer)
    {
        ++client->reconn.attempts;
        client->reconn.countdown =
                _jw_client_reconn_next_countdown(
                            _reconn_base_countdown(client),
                            client->reconn.attempts);
        // setup workq timer
        if (!jw_workq_item_create(client->workq,
                                  _reconn_on_execute,
                                  &client->reconn.timer,
                                  &err) ||
            !jw_workq_item_set_delay(client->reconn.timer,
                                     client->reconn.countdown,
                                     &err))
        {
            jw_log_err(JW_LOG_WARN,
                       &err,
                       "Reconnect timer could not be created");
            _reconn_cancel_timer(client);
            return;
        }

        // no cleaner needed for client
        jw_workq_item_set_data(client->reconn.timer, client, NULL);

        if (!jw_workq_item_append(client->reconn.timer, &err))
        {
            jw_log_err(JW_LOG_WARN,
                       &err,
                       "Reconnect timer could not be enqueued");
            _reconn_cancel_timer(client);
            return;
        }

        jw_log(JW_LOG_DEBUG,
               "Scheduled reconnect attempt in %"PRIu64" milliseconds",
               client->reconn.countdown);
        _trigger_reconnect_changed(client, JW_CLIENT_RECONNECT_PENDING);
    }
}

static void _reconn_on_connected(jw_client *client)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;
    client->reconn.config = jw_client_get_config(client);
    client->reconn.attempts = client->reconn.countdown = 0;
    _reconn_set_jid(client, client->jid, NULL);
    client->status.reconnecting = false;
    client->reconn.status = JW_CLIENT_RECONNECT_CANCELED;
}

static inline bool _reconn_should_reconnect(jw_client *client, jw_dom_node *err)
{
    jw_log_dom(JW_LOG_DEBUG,
               err,
               "Checking if reconnect should be attempted for err: ");
    return err &&
           _reconn_enabled(client) &&
           _jw_client_reconn_is_disconnect_error(err);
}

static void _reconn_on_before_disconnect(jw_client *client, jw_dom_node *err)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;
    //reconnect if enabled and recoverable error
    client->status.reconnecting = _reconn_should_reconnect(client, err);
}

void _reconn_on_execute(jw_workq_item *item, void *data)
{
    jw_client *client = data;
    PUSH_CLIENT_NDC;
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    jw_workq_item_destroy(item);
    client->reconn.timer = NULL;
    _reconn_start(client);
    POP_CLIENT_NDC;
}

/********************************************
 * Binding functions
 *******************************************/
static jw_dom_node *_create_bind(jw_jid *jid, jw_err *err)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    jw_dom_ctx *domCtx;
    jw_dom_node *iqDom;
    jw_dom_node *bindDom;
    jw_dom_node *resourceDom;
    jw_dom_node *resourceText;
    const char *resourcePart = jid ? jw_jid_get_resource(jid) : NULL;

    if (!jw_dom_context_create(&domCtx, err))
    {
        return NULL;
    }

    if (!jw_dom_element_create(domCtx, JW_CLIENT_IQ, &iqDom, err) ||
        !jw_dom_set_attribute(iqDom, "{}id", "random_number", err) ||
        !jw_dom_set_attribute(iqDom, "{}type", "set", err) ||
        !jw_dom_element_create(domCtx, JW_CLIENT_BIND, &bindDom, err) ||
        !jw_dom_add_child(iqDom, bindDom, err))
    {
        goto _create_bind_fail_label;
    }

    //use resource if provided
    if (resourcePart &&
        (!jw_dom_element_create(domCtx,
                                JW_CLIENT_BIND_RESOURCE,
                                &resourceDom,
                                err) ||
         !jw_dom_add_child(bindDom, resourceDom, err) ||
         !jw_dom_text_create(domCtx, resourcePart, &resourceText, err) ||
         !jw_dom_add_child(resourceDom, resourceText, err)))
    {
        goto _create_bind_fail_label;
    }

    return iqDom;

_create_bind_fail_label:
    jw_dom_context_destroy(domCtx);
    return NULL;
}

static jw_dom_node *_create_presence(jw_err* err)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    jw_dom_ctx *domCtx;
    jw_dom_node *presDom;

    if (!jw_dom_context_create(&domCtx, err))
    {
        return NULL;
    }

    if (!jw_dom_element_create(domCtx, JW_CLIENT_PRESENCE, &presDom, err))
    {
        jw_dom_context_destroy(domCtx);
        return NULL;
    }

    return presDom;
}

static bool _do_bind(jw_client *client, jw_err *err)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    jw_dom_node *sendNode = _create_bind(client->jid, err);
    if (!sendNode)
    {
        return false;
    }

    if (!jw_stream_send(client->stream, sendNode, err))
    {
        jw_log_err(JW_LOG_WARN, err, "could not send the bind dom");
        return false;
    }

    return true;
}

/**
 * Finish connection by resuming a previous session or starting a new one.
 * Changes client state to OPENED and attempts to enable SM if needed.
 * Fires clientSessionResumed if resuming session, otherwise changes
 * client status to connected and fires clientCOnnected and clientStatusChange
 * events.
 *
 * Called from conclusion of bind or resume
 */
static bool _finish_connect(jw_client *client, bool resuming, jw_err *err)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    // update reconnection connection information
    _reconn_on_connected(client);

    if (!_client_state_change(client, OPENED, err))
    {
        return false;
    }

    if (resuming)
    {
        jw_log(JW_LOG_DEBUG, "resuming previous session");

        jw_event *evt = jw_client_event(client,
                                             JW_CLIENT_EVENT_SESSION_RESUMED);
        if (!jw_event_trigger(evt, NULL, NULL, NULL, err))
        {
            jw_log_err(JW_LOG_WARN, err,
                       "unable to trigger session resumed event");
            return false;
        }

        // resumed; resend any unacked stanzas
        _stanza_queue stanza_node = (&client->stream_mgmt_state)->unacked_stanzas;
        while (NULL != stanza_node)
        {
            if (!_send_tracked_stanza(client, stanza_node->stanza, false, err))
            {
                jw_log_err(JW_LOG_WARN, err,
                           "failed to resend stanzas enqueued while paused");
                return false;
            }
            stanza_node = stanza_node->next;
        }

        if (!_do_sm_r_if_required(client, true, err))
        {
            jw_log_err(JW_LOG_WARN, err, "failed to send r element");
            return false;
        }
    }
    else
    {
        jw_log(JW_LOG_DEBUG, "starting new session");
        _set_next_status(&client->status, JW_CLIENT_CONNECTED);
        _trigger_status_changed(client);

        // clear stream management counters and any stanzas that were
        // accumulated in the queue while we were paused
        _stream_mgmt_state sm_state = &client->stream_mgmt_state;
        sm_state->num_received_stanzas     = 0;
        sm_state->num_server_acked_stanzas = 0;
        sm_state->num_unacked_stanzas      = 0;

        _stanza_queue cur_node = client->stream_mgmt_state.unacked_stanzas;
        while (NULL != cur_node)
        {
            _unacked_stanza_node_pop(&cur_node);
        }
        client->stream_mgmt_state.unacked_stanzas = NULL;
        client->stream_mgmt_state.unacked_stanzas_tail = NULL;

        jw_dom_node *sendNode = _create_presence(err);
        if (!sendNode)
        {
            return false;
        }
        if (!_send_tracked_stanza(client, sendNode, true, err))
        {
            jw_log_err(JW_LOG_WARN, err, "could not send presence dom");
            jw_dom_context_destroy(jw_dom_get_context(sendNode));// ??
            return false;
        }
    }

    return true;
}

/********************************************
 * Stream event callbacks
 *******************************************/

/*
 * stream_opened event is triggered when <stream:features/> is received.
 * <starttls/> may be a child of the first <stream:features/> encountered.
 * On successful STARTTLS we expect the opened event to fire a second time
 * with sasl, a third time with bind
 *
 * Using two event handlers to handle the first feature stanza differently
 * than any subsequent <stream:features/>.
 */

/**
 * Handle <stream:features/> for sasl and bind
 */
static void _stream_features_sasl_int(jw_dom_node *node, jw_client *client)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(client);
    assert(!client->mech_instance);

    jw_err err;

    jw_log(JW_LOG_DEBUG, "stream opened for sasl");
    jw_log_dom(JW_LOG_DEBUG, node, "handling sasl features: ");

    jw_htable       *config       = jw_client_get_config(client);
    jw_sasl_factory *sasl_factory = jw_htable_get(config,
                                                 JW_CLIENT_CONFIG_SASL_FACTORY);
    jw_dom_node     *mechanisms   = jw_dom_get_first_element(
                                                 node, JW_CLIENT_SASL_MECHS);
    // <features><mechanisms/></features>
    if (mechanisms && jw_sasl_factory_get_best_mech_in_dom(
            sasl_factory, mechanisms, config, &client->mech_instance, &err))
    {
        // mechanisms dom found and parsed
        if (NULL == client->mech_instance)
        {
            jw_log(JW_LOG_WARN, "could not agree on sasl mechanism");
            JABBERWERX_ERROR(&err, JW_ERR_NOT_AUTHORIZED);
            //CLOSED_ERROR state

            jw_dom_ctx  *err_ctx;
            jw_dom_node *failure_node;
            if (!jw_dom_context_create(&err_ctx, &err))
            {
                jw_log_err(JW_LOG_WARN, &err,
                           "failed to create context for failure node");
            }
            else
            {
                if (!_jw_sasl_mech_sasl_err_to_failure_node(
                            JW_SASL_ERR_MECHANISM_TOO_WEAK,
                            err_ctx, &failure_node, &err))
                {
                    jw_log_err(JW_LOG_WARN, &err,
                               "failed to create failure node");
                }
                else
                {
                    _jw_stream_set_error_node_if_not_set(
                            client->stream, err.code, failure_node);
                }

                jw_dom_context_destroy(err_ctx);
            }

            goto _stream_event_sasl_opened_cb_int_fail_label;
        }
        else
        {
            jw_log(JW_LOG_DEBUG, "authenticating with SASL mechanism: %s",
                   jw_sasl_mech_get_name(jw_sasl_mech_instance_get_mech(
                        client->mech_instance)));
            if (!jw_sasl_mech_instance_evaluate(
                            client->mech_instance, NULL,
                            _sasl_mech_evaluate_complete, client, &err))
            {
                jw_log_err(JW_LOG_WARN, &err, "failed to send auth dom");
                goto _stream_event_sasl_opened_cb_int_fail_label;
            }
        }
    }
    else if (!mechanisms)
    {
        jw_log(JW_LOG_WARN, "no mechanisms in features");
        JABBERWERX_ERROR(&err, JW_ERR_NOT_AUTHORIZED)
        goto _stream_event_sasl_opened_cb_int_fail_label;
    }
    return;

_stream_event_sasl_opened_cb_int_fail_label:
    _close_on_error(client, &err);
}

static void _stream_features_sasl(jw_event_data event, void *arg)
{
    jw_dom_node *streamNode = event->data;
    jw_client *client = arg;

    PUSH_CLIENT_NDC;
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    _stream_features_sasl_int(streamNode, client);

    POP_CLIENT_NDC;
}

static void _stream_event_recv_resume(jw_event_data event, void *arg)
{
    jw_dom_node **data = event->data;
    jw_client   *client = arg;
    jw_err err;

    PUSH_CLIENT_NDC;
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(data && data[0]);
    const char *ename = jw_dom_get_ename(data[0]);
    if (0 == jw_strcmp(ename, JW_CLIENT_SM_RESUMED))
    {
        // syncup acks
        if (!_handle_sm_a(client, data[0], &err))
        {
            jw_log_err(JW_LOG_WARN,&err,
                       "Could not update sm counts from <resumed/>:");
            _close_on_error(client, &err);
        }
        else if (!_finish_connect(client, true, &err))
        {
            jw_log_err(JW_LOG_WARN,&err,
                       "Could not resume previous session:");
            _close_on_error(client, &err);
        }
        // technically there could be additional packets after resumed,
        // packets may be routed at any time after a session is established.
        else if (data[1])
        {
            jw_log(JW_LOG_WARN, "extra stanzas found with <resumed/>");
            //pass off extras to default handler
            _stream_event_recv(event, &data[1]);
        }
    }
    else
    {
        jw_log(JW_LOG_DEBUG, "session resumption not possible");
        if (0 == jw_strcmp(ename, JW_CLIENT_SM_FAILED))
        {
            // report that resumption has failed and reset state
            _reconn_cancel(client);

            // on resume failure try normal binding
            jw_log_dom(JW_LOG_WARN, data[0], "resume failed: ");
            if (!_client_state_change(client, FEAT_BIND, &err))
            {
                jw_log_err(JW_LOG_WARN, &err, "failed to change client state");
                _close_on_error(client, &err);
            }
            else if (!_do_bind(client, &err))
            {
                jw_log_err(JW_LOG_WARN, &err, "failed to send bind");
                _close_on_error(client, &err);
            }
        }
        else
        {
            jw_log_dom(JW_LOG_WARN,
                       data[0],
                       "received unknown protocol during resumption: ");
            JABBERWERX_ERROR(&err, JW_ERR_PROTOCOL);
            _close_on_error(client, &err);
        }
    }

    POP_CLIENT_NDC;
}

static void _stream_features_resume(jw_event_data event, void *data)
{
    jw_client  *client = data;
    PUSH_CLIENT_NDC;
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(event);

    jw_dom_node *node = event->data;
    jw_err err;

    assert(node);

    if (node && (NULL != jw_dom_get_first_element(node, JW_CLIENT_BIND)))
    {
        jw_log(JW_LOG_DEBUG, "attempting to resume previous session");
        // reconnecting and resuming enabled?
        if (_reconn_reconnecting(client) &&
            (0 != (_jw_client_get_stream_mgmt_state(client)->flags & SM_RESUME_ENABLED)))
        {
            if (_sm_do_resume(client, &err))
            {
                POP_CLIENT_NDC;
                return;
            }
            jw_log_err(JW_LOG_WARN, &err, "failed to start resume");
        }
    }
    jw_log(JW_LOG_DEBUG, "resumption is not possible, starting new session");
    //attempt normal bind if resumed failed
    //move to FEAT_BIND state and pass feats on to bind feats handler
    if (!_client_state_change(client, FEAT_BIND, &err))
    {
        jw_log_err(JW_LOG_WARN, &err, "failed to change state from FEAT_RESUME to FEAT_BIND");
    }
    _stream_features_bind(event, data);
    POP_CLIENT_NDC;
}

static void _stream_features_bind(jw_event_data event, void *arg)
{
    jw_client  *client = arg;
    PUSH_CLIENT_NDC;
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    jw_err            err;
    jw_dom_node *node = event->data;

    assert(node);

    if (jw_dom_get_first_element(node, JW_CLIENT_BIND))
    {
        // record if stream management is supported by the server
        jw_dom_node *sm_node = jw_dom_get_first_element(node, JW_CLIENT_SM);
        if (NULL == sm_node)
        {
            jw_log(JW_LOG_DEBUG,
                   "stream management not supported by server");
        }
        else
        {
            jw_log(JW_LOG_DEBUG,  "stream management supported by server");
            client->stream_mgmt_state.flags |= SM_SUPPORTED;

            if (NULL != jw_dom_get_first_element(sm_node, JW_CLIENT_SM_REQUIRED))
            {
                client->stream_mgmt_state.flags |= SM_REQUIRED;
            }
        }

        if (!_do_bind(client, &err))
        {
            jw_log_err(JW_LOG_WARN, &err, "failed to send bind request");
            _close_on_error(client, &err);
        }
    }
    else
    {
        JABBERWERX_ERROR(&err, JW_ERR_PROTOCOL);
        jw_log_dom(JW_LOG_WARN, node, "expected bind feature");
        _close_on_error(client, &err);
    }
    POP_CLIENT_NDC;
}

/**
 * stream elemrecv callback. Expect bind result.
 * bind <stream:error/> and <error/> are caught here as well.
 */
static void _stream_event_recv_bind(jw_event_data event, void *arg)
{
    jw_client *client = arg;

    PUSH_CLIENT_NDC;
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(event);
    jw_dom_node **data = event->data;
    jw_dom_node *node = NULL;
    jw_dom_node *stanza = NULL;
    jw_err err;

    assert(data && data[0]);

    stanza = data[0];

    _stream_mgmt_state sm_state = &client->stream_mgmt_state;

    if (_reconn_reconnecting(client) && _sm_should_resume(client))
    {
        node = jw_dom_get_first_element(stanza, JW_CLIENT_SM_RESUMED);

        if (!node)
        {
            node = jw_dom_get_first_element(stanza, JW_CLIENT_ERROR);
            // if there was a resume error, retry bind (note no state change
            // to keep correct received handlers)
            if (!node)
            {
                jw_log(JW_LOG_WARN,
                      "Received unknown protocol during resume attempt");
            }
            else
            {
                jw_log_dom(JW_LOG_WARN,
                           node,
                           "error returned from server during resume attempt");
            }

            if (!_do_bind(client, &err))
            {
                jw_log_err(JW_LOG_WARN, &err, "failed to bind");
                goto _stream_event_recv_bind_fail_label;
            }
            goto _stream_event_recv_bind_return_label;
        }

    }
    else
    {
        node = jw_dom_get_first_element(stanza, JW_CLIENT_BIND);
        if (!node)
        {
            node = jw_dom_get_first_element(stanza, JW_STREAM_ENAME_ERROR);
            jw_log_dom(JW_LOG_WARN,
                       node,
                       "Error returned from server during bind attempt");
            JABBERWERX_ERROR(&err, JW_ERR_PROTOCOL);
            _jw_stream_set_error_node_if_not_set(client->stream,
                                                 err.code,
                                                 node);
            goto _stream_event_recv_bind_fail_label;
        }

        // modify client's jid as needed
        node = jw_dom_get_first_element(node, JW_CLIENT_BIND_JID);
        const char *jidstr = node ? jw_dom_get_first_text(node) : NULL;
        // badly formatted bind result? could probably assert
        if (!jidstr || !strlen(jidstr))
        {
            // err_dom set to internal server error?
            jw_log(JW_LOG_WARN, "Did not receive bound JID from server");
            JABBERWERX_ERROR(&err, JW_ERR_PROTOCOL);
            goto _stream_event_recv_bind_fail_label;
        }

        jw_log(JW_LOG_DEBUG, "Received bind JID: [%s].", jidstr);

        if (client->jid)
        {
            jw_jid_destroy(client->jid);
        }
        client->jid = _new_jid(jw_client_get_config(client), jidstr, &err);
        if (!client->jid)
        {
            // OOM || BAD JID
            jw_log_err(JW_LOG_WARN,
                       &err,
                       "Could not create jid object from bound jid string");
            goto _stream_event_recv_bind_fail_label;
        }
        // enable stream management as needed
        if (0 != (SM_SUPPORTED & sm_state->flags) && !_do_sm(client, &err))
        {
            jw_log_err(JW_LOG_WARN, &err,
                    "failed to init stream management");
            goto _stream_event_recv_bind_fail_label;
        }
    }

    // finish sets state to OPENED
    if (!_finish_connect(client, false, &err))
    {
        jw_log_err(JW_LOG_WARN,
                   &err,
                   "Could not finish connection after binding");
         goto _stream_event_recv_bind_fail_label;
    }
    // technically there could be additional packets after a successful bind
    // packets may be routed at any time after a session is established.
    if (*(data + 1))
    {
        jw_log(JW_LOG_WARN, "extra stanzas found with bind");
        //pass off extras to default handler
        _stream_event_recv(event, &(*(data + 1)));
    }
_stream_event_recv_bind_return_label:
    POP_CLIENT_NDC;
    return;

_stream_event_recv_bind_fail_label:
    _close_on_error(client, &err);
    POP_CLIENT_NDC;
}

static void _stream_event_closed(jw_event_data event, void *data)
{
    jw_client *client = data;

    PUSH_CLIENT_NDC;
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(event);
    jw_dom_node *err_dom = event->data;
    jw_err            err;

    // todo unbind stream event listeners
    jw_log_dom(JW_LOG_INFO, err_dom, "stream closed; err_dom=");

    jw_tracker_clear(client->tracker);
    jw_timer_cancel(client->stream_mgmt_state.ack_request_timer);

    client->status.reconnecting = _reconn_should_reconnect(client, err_dom);
    if (client->status.reconnecting)
    {
        //todo status.reconnecting is probably no longer needed
        client->status.reconnecting = false;
        _reconn_pending(client);

        // trigger paused event
        if (_sm_should_resume(client))
        {
            if (err_dom)
            {
                if (!jw_dom_context_retain(jw_dom_get_context(err_dom), &err))
                {
                    jw_log_err(JW_LOG_WARN, &err, "unable to retain err_dom context");
                    _close_on_error(client, &err);
                }
            }
            if (!jw_states_change(client->states, PAUSED, NULL, NULL, &err))
            {
                jw_log_err(JW_LOG_WARN, &err, "Client unable to change to PAUSED state");
                _close_on_error(client, &err);
                POP_CLIENT_NDC;
                return;
            }

            jw_event *evt = jw_client_event(client,
                                                 JW_CLIENT_EVENT_SESSION_PAUSED);
            if (!jw_event_trigger(evt, err_dom,
                                  _destroy_context_result_cb, NULL, &err))
            {
                jw_log_err(JW_LOG_WARN, &err,
                           "unable to trigger disconnected event");
                _close_on_error(client, &err);
            }
            POP_CLIENT_NDC;
            return; //don't trigger disconnected
        }
    }
    client->status.reconnecting = false;

    //trigger disconnected status change
    _set_next_status(&client->status, JW_CLIENT_DISCONNECTED);
    if (err_dom)
    {
        if (!jw_dom_context_retain(jw_dom_get_context(err_dom), &err))
        {
            jw_log_err(JW_LOG_WARN, &err, "unable to retain err_dom context");
            _close_on_error(client, &err);
            POP_CLIENT_NDC;
            return;
        }

        client->status.err_dom = err_dom;
    }
    _trigger_status_changed(client);

    POP_CLIENT_NDC;
}

#define CLIENT_RECEIVED_EVENTS_IQ_INDEX 1
#define CLIENT_RECEIVED_EVENTS_PRESENCE_INDEX 5
#define CLIENT_RECEIVED_EVENTS_MESSAGE_INDEX 9

static const char* CLIENT_RECEIVED_EVENTS[] = {
    NULL,

    JW_CLIENT_EVENT_BEFORE_IQ_RECEIVED,
    JW_CLIENT_EVENT_IQ_RECEIVED,
    JW_CLIENT_EVENT_AFTER_IQ_RECEIVED,
    NULL,

    JW_CLIENT_EVENT_BEFORE_PRESENCE_RECEIVED,
    JW_CLIENT_EVENT_PRESENCE_RECEIVED,
    JW_CLIENT_EVENT_AFTER_PRESENCE_RECEIVED,
    NULL,

    JW_CLIENT_EVENT_BEFORE_MESSAGE_RECEIVED,
    JW_CLIENT_EVENT_MESSAGE_RECEIVED,
    JW_CLIENT_EVENT_AFTER_MESSAGE_RECEIVED,
    NULL
};

static void _client_dom_cb(jw_event_data evt,
                           bool result,
                           void *arg);

static bool _client_dom_cb_handle(jw_client *client,
                                  jw_dom_node *node,
                                  bool result,
                                  uintptr_t index,
                                  jw_err *err)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    const char *event_name = CLIENT_RECEIVED_EVENTS[index];

    if (!result && (event_name != NULL))
    {
        jw_event   *evt = jw_client_event(client, event_name);
        jw_dom_ctx *ctx = jw_dom_get_context(node);

        // ensure the node doesn't disappear by the time the event is handled
        if (!jw_dom_context_retain(ctx, err))
        {
            return false;
        }

        ++index;
        if (!jw_event_trigger(evt, node, _client_dom_cb, (void*)index, err))
        {
            jw_dom_context_destroy(ctx);
            return false;
        }
    }

    return true;
}

static void _client_dom_cb(jw_event_data evt,
                           bool result,
                           void *arg)
{
    jw_err err;
    uintptr_t index = (uintptr_t)arg;
    jw_client *client = evt->source;
    jw_dom_node *node = evt->data;

    PUSH_CLIENT_NDC;
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    if (!_client_dom_cb_handle(client, node, result, index, &err))
    {
        _close_on_error(client, &err);
        return;
    }

    // undo a level of context retaining
    jw_dom_context_destroy(jw_dom_get_context(node));

    POP_CLIENT_NDC;
}

static void _stream_event_recv(jw_event_data event, void *data)
{
    jw_dom_node **nodes = event->data;
    jw_client *client = data;

    jw_err err;
    bool retval = true;

    PUSH_CLIENT_NDC;
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    for (int index = 0; nodes[index] != NULL; index++)
    {
        jw_dom_node *node = nodes[index];
        const char *ename = jw_dom_get_ename(node);
        uintptr_t counter = 0;

        if (0 == jw_strcmp(ename, JW_CLIENT_IQ))
        {
            counter = CLIENT_RECEIVED_EVENTS_IQ_INDEX;
        }
        else if (0 == jw_strcmp(ename, JW_CLIENT_PRESENCE))
        {
            counter = CLIENT_RECEIVED_EVENTS_PRESENCE_INDEX;
        }
        else if (0 == jw_strcmp(ename, JW_CLIENT_MESSAGE))
        {
            counter = CLIENT_RECEIVED_EVENTS_MESSAGE_INDEX;
        }
        else if (0 == jw_strcmp(ename, JW_CLIENT_SM_ENABLED))
        {
            _stream_mgmt_state sm_state = &client->stream_mgmt_state;

            jw_log(JW_LOG_DEBUG, "enabling stream management");

            sm_state->flags |= SM_ENABLED;

            if (0 == jw_strcmp("true", jw_dom_get_attribute(node, "resume")))
            {
                sm_state->flags |= SM_RESUME_ENABLED;
            }

            sm_state->resume_id =
                    jw_data_strdup(jw_dom_get_attribute(node, "id"));
            sm_state->resume_location =
                    jw_data_strdup(jw_dom_get_attribute(node, "location"));

            // reset client "h" value to zero in case server has sent stanzas
            // prior to sending the 'enabled' element
            sm_state->num_received_stanzas = 0;

            // fire off an ack request and an ack request timeout in case we've
            // already passed our request threshold; this will get us back on
            // track
            retval = _do_sm_r_if_required(client, true, &err);
            if (!retval)
            {
                break;
            }

            if (0 < sm_state->num_unacked_stanzas)
            {
                jw_timer_mark_activity(sm_state->ack_request_timer);
            }
        }
        else if (0 == jw_strcmp(ename, JW_CLIENT_SM_FAILED))
        {
            jw_log_dom(JW_LOG_WARN, node, "server refused stream management: ");
            retval = true;
        }
        else if (0 == jw_strcmp(ename, JW_CLIENT_SM_A))
        {
            retval = _handle_sm_a(client, node, &err);
            if (!retval)
            {
                break;
            }
        }
        else if (0 == jw_strcmp(ename, JW_CLIENT_SM_R))
        {
            jw_log(JW_LOG_DEBUG, "acking sm request with h=%u",
                   client->stream_mgmt_state.num_received_stanzas);
            retval = _do_sm_a(client, &err);
            if (!retval)
            {
                break;
            }
        }
        else
        {
            jw_log_dom(JW_LOG_WARN, node, "received unknown element: '%s': ",
                       ename);
            JABBERWERX_ERROR(&err, JW_ERR_PROTOCOL);
            retval = false;
        }

        if (0 < counter)
        {
            ++client->stream_mgmt_state.num_received_stanzas;
            retval = _client_dom_cb_handle(client, node, false, counter, &err);
            if (!retval)
            {
                break;
            }
        }
    }

    if (!retval)
    {
        jw_log_err(JW_LOG_WARN, &err, "error processing received element");
        _close_on_error(client, &err);
    }

    POP_CLIENT_NDC;
}

static void _stream_event_sent(jw_event_data event, void *data)
{
    jw_dom_node **nodes = event->data;
    jw_client *client = data;

    PUSH_CLIENT_NDC;
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    // notify client for each recently sent stanza
    for (int idx = 0; nodes[idx] != NULL; ++idx)
    {
        jw_dom_node *stanza = nodes[idx];
        const char * ename = jw_dom_get_ename(stanza);
        const char * eventName;

        if (0 == jw_strcmp(JW_CLIENT_PRESENCE, ename))
        {
            eventName = JW_CLIENT_EVENT_PRESENCE_SENT;
        }
        else if (0 == jw_strcmp(JW_CLIENT_MESSAGE, ename))
        {
            eventName = JW_CLIENT_EVENT_MESSAGE_SENT;
        }
        else if (0 == jw_strcmp(JW_CLIENT_IQ_LOCALNAME, ename))
        {
            eventName = JW_CLIENT_EVENT_IQ_SENT;
        }
        else
        {
            // sent stanza for which we do not need to notify the user (such as
            // a stream management stanza)
            continue;
        }

        jw_event *sentEvent = jw_event_dispatcher_get_event(
                                        client->dispatch, eventName);

        // notify the client
        // TODO: do we need a callback for this?  do we care if the client
        // TODO:   doesn't handle it?
        jw_err     err;
        jw_dom_ctx *ctx = jw_dom_get_context(stanza);
        if (!jw_dom_context_retain(ctx, &err))
        {
            jw_log(JW_LOG_WARN, "could not retain client stanza ctx");
            _close_on_error(client, &err);
            break;
        }

        if (!jw_event_trigger(sentEvent, stanza,
                              _destroy_context_result_cb, NULL, &err))
        {
            // set error and disconnect
            jw_dom_context_destroy(ctx);
            _close_on_error(client, &err);
            break;
        }
    }

    POP_CLIENT_NDC;
}

static void _send_stanza_cb(jw_event_data evt, bool result, void *arg)
{
    jw_err err;
    jw_client *client = arg;

    PUSH_CLIENT_NDC;
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    // if already handled by a previous filter callback, just free the dom
    // context and return early
    if (result)
    {
        jw_dom_context_destroy(jw_dom_get_context(evt->data));
        goto _send_stanza_cb_finish_label;
    }

    // otherwise, write the stanza to the stream
    // stream will trigger an event when it has sent the stanza and destroy the
    // stanza context for us
    if (!_send_tracked_stanza(client, evt->data, true, &err))
    {
        _close_on_error(client, &err);
    }

_send_stanza_cb_finish_label:
    POP_CLIENT_NDC;
}

static void _client_destroyed_event_result(jw_event_data evt, bool result,
                                           void *arg)
{
    UNUSED_PARAM(evt);
    UNUSED_PARAM(result);

    jw_client *client = arg;
    assert(client);

    PUSH_CLIENT_NDC;
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    _clean_stream_mgmt_state(&client->stream_mgmt_state);
    _set_next_status(&client->status, JW_CLIENT_DISCONNECTED);
    _client_state_finalize(client);

    if (client->reconn.timer)
    {
        jw_workq_item_destroy(client->reconn.timer);
        client->reconn.timer = NULL;
    }

    if (client->tls_ctx)
    {
        jw_tls_context_destroy(client->tls_ctx);
        client->tls_ctx = NULL;
    }

    if (client->tracker)
    {
        // unbind of JW_CLIENT_EVENT_BEFORE_IQ_RECEIVED not needed,
        // since dispatcher will be destroyed below
        jw_tracker_destroy(client->tracker);
        client->tracker = NULL;
    }

    if (client->dispatch)
    {
        jw_event_dispatcher_destroy(client->dispatch);
        client->dispatch = NULL;
    }

    jw_data_free(client);

    POP_CLIENT_NDC;
}

static void _stream_destroyed_cb_int(jw_client *client)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;
    jw_err err;

    assert(client);

    if (client->stream)
    {
        // have to do this while stream and its events are still guaranteed to
        // exist as finalize unbinds stream callbacks
        _client_state_finalize(client);
        if (!client->destroying)
        {
            // Set client's state back to initial conditions
            if (!_client_state_initialize(client, &err))
            {
                jw_log_err(JW_LOG_WARN,
                           &err,
                           "client state object could not be initialized");
            }
        }
        client->stream = NULL;
    }

    if (client->destroy_trigger_data)
    {
        if (client->destroying)
        {
            // must be done while config is still guaranteed to exist (since that is
            // where the jid context and sasl factory are)
            if (client->jid)
            {
                jw_jid_destroy(client->jid);
                client->jid = NULL;
            }
            if (client->mech_instance)
            {
                jw_sasl_mech_instance_destroy(client->mech_instance);
                client->mech_instance = NULL;
            }

            // ensure we don't keep any references to the soon-to-be-destroyed
            // config
            client->reconn.config = NULL;

            jw_event *evt;
            if (client->dispatch &&
                (evt = jw_client_event(client, JW_CLIENT_EVENT_DESTROYED)))
            {
                jw_event_trigger_prepared(evt, NULL, _client_destroyed_event_result,
                                            client, client->destroy_trigger_data);
            }
            else
            {
                jw_event_unprepare_trigger(client->destroy_trigger_data);
                _client_destroyed_event_result(NULL, false, client);
            }
        }
    }
    else
    {
        // if _destroyTriggerData isn't initialized, nothing else should be
        assert(!client->dispatch);
        assert(!client->stream);
        assert(!client->tls_ctx);
        assert(!client->tracker);
        jw_data_free(client);
    }
}

static void _stream_destroyed_cb(jw_event_data evt, void *arg)
{
    UNUSED_PARAM(evt);

    assert(arg);
    jw_client *client = arg;

    PUSH_CLIENT_NDC;
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    _stream_destroyed_cb_int(client);

    POP_CLIENT_NDC;
}

static const char* CLIENT_EVENTS[] = {
    JW_CLIENT_EVENT_STATUSCHANGED,
    JW_CLIENT_EVENT_CONNECTED,
    JW_CLIENT_EVENT_DISCONNECTED,
    JW_CLIENT_EVENT_DESTROYED,
    JW_CLIENT_EVENT_SESSION_PAUSED,
    JW_CLIENT_EVENT_SESSION_RESUMED,

    JW_CLIENT_EVENT_RECONNECT_STATUSCHANGED,

    JW_CLIENT_EVENT_BEFORE_IQ_RECEIVED,
    JW_CLIENT_EVENT_IQ_RECEIVED,
    JW_CLIENT_EVENT_AFTER_IQ_RECEIVED,
    JW_CLIENT_EVENT_BEFORE_IQ_SENT,
    JW_CLIENT_EVENT_IQ_SENT,

    JW_CLIENT_EVENT_BEFORE_PRESENCE_RECEIVED,
    JW_CLIENT_EVENT_PRESENCE_RECEIVED,
    JW_CLIENT_EVENT_AFTER_PRESENCE_RECEIVED,
    JW_CLIENT_EVENT_BEFORE_PRESENCE_SENT,
    JW_CLIENT_EVENT_PRESENCE_SENT,

    JW_CLIENT_EVENT_BEFORE_MESSAGE_RECEIVED,
    JW_CLIENT_EVENT_MESSAGE_RECEIVED,
    JW_CLIENT_EVENT_AFTER_MESSAGE_RECEIVED,
    JW_CLIENT_EVENT_BEFORE_MESSAGE_SENT,
    JW_CLIENT_EVENT_MESSAGE_SENT,

    NULL
};


/********************************************
 * Private API functions
 *******************************************/
_stream_mgmt_state _jw_client_get_stream_mgmt_state(jw_client *client)
{
    assert(client);
    return &client->stream_mgmt_state;
}


/**
 * Get the given client's reconnect state
 */
jw_client_reconnect_status *_jw_client_reconnect_state(jw_client *client)
{
    assert(client);
    return &client->reconn;
}

/**
 * Computing countdown for the next reconnection attempt
 *
 *
 * base*2^(attempt - 1) + rand(base/2)
 */
static inline uint32_t _rand_uint32(uint32_t bound)
{
    uint32_t rand;
    evutil_secure_rng_get_bytes((void*)&rand,
                                sizeof(rand));
    return (uint32_t)(((uint64_t)bound * (uint64_t)rand) / UINT32_MAX);
}

/**
 * Calculate the next reconnect countdown.
 *
 * currently returns    min(2^(attempt - 1)*base,
 *                          JW_CLIENT_DEFAULT_RECONNECT_MAX_COUNTDOWN_MS)
 *                       +- rand(base/2)
 *                       for attempt in [1, 32]
 *
 * This function ensures the result is always less than or equal to the
 * JW_CLIENT_DEFAULT_RECONNECT_MAX_COUNTDOWN_MS + rand(base/2).
 *
 */
uint32_t _jw_client_reconn_next_countdown(uint32_t base,
                                          uint32_t attempt)
{
    JW_LOG_TRACE_FUNCTION("base: %u, attempt: %u", base, attempt);

    uint64_t nbase;  //the nth base computed based on # of attempts

    if (0 == attempt || 0 == base)
    {
        return 0;
    }

    //limit shifts to sizeof uint32_t
    if ((sizeof(uint32_t)*BITS_PER_BYTE + 1) <= attempt)
    {
        attempt = sizeof(uint32_t)*BITS_PER_BYTE;
    }

    //skip doubling if base already > default max
    if (base > JW_CLIENT_DEFAULT_RECONNECT_MAX_COUNTDOWN_MS)
    {
        jw_log(JW_LOG_WARN, "reconnect base > maximum allowed");
        return JW_CLIENT_DEFAULT_RECONNECT_MAX_COUNTDOWN_MS;
    }

    nbase = base;
    // skip shifting 0 bits
    if (attempt > 1)
    {
        nbase *= (1 << (attempt - 1)); //nbase in [base, 2^64]
    }

    //upper bound
    if (nbase > JW_CLIENT_DEFAULT_RECONNECT_MAX_COUNTDOWN_MS)
    {
        nbase = JW_CLIENT_DEFAULT_RECONNECT_MAX_COUNTDOWN_MS;
    }

    //uint32 overflow check,
    //hit if JW_CLIENT_DEFAULT_RECONNECT_MAX_COUNTDOWN_MS > UINT32_MAX/2
    if (nbase > (UINT32_MAX - base/2))
    {
        jw_log(JW_LOG_WARN, "Reconnect countdown overflow");
        nbase = JW_CLIENT_DEFAULT_RECONNECT_MAX_COUNTDOWN_MS;
    }

    //nbase is in [base, 2^16], base > 0
    return nbase - base/2 + _rand_uint32(base);
}

/**
 * disconnect reason discriminator. Checks the given condition and returns true
 * if a reconnect attempt should be started, else false
 * a null error (no error) does not cause a reconnection.
 * This function check errors that occurred after connection succeeded, the
 * initial error that starts reconnection attempts
 */
bool _jw_client_reconn_is_disconnect_error(jw_dom_node *error)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;
    return error &&
          (jw_dom_get_first_element(error, JW_STREAM_ERROR_REMOTE_CONN_FAILED) ||
           jw_dom_get_first_element(error, JW_STREAM_ERROR_CONN_TIMEOUT) ||
           jw_dom_get_first_element(error, JW_STREAM_ERROR_POLICY_VIOLATION) ||
           jw_dom_get_first_element(error, JW_STREAM_ERROR_RESET));
}

/********************************************
 * Public API functions
 *******************************************/
JABBERWERX_API bool jw_client_create(jw_workq   *workq,
                                     jw_client **retclient,
                                     jw_err    *err)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(retclient);

    jw_client *client = jw_data_malloc(sizeof(struct _jw_client));
    if (!client)
    {
        JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
        return false;
    }
    memset(client, 0, sizeof(struct _jw_client));

    PUSH_CLIENT_NDC;
    jw_log(JW_LOG_TRACE, "creating new client");

    if (!jw_event_dispatcher_create(client, workq, &client->dispatch, err))
    {
        goto jw_client_create_fail_label;
    }

    if (!jw_event_prepare_trigger(
            client->dispatch, &client->destroy_trigger_data, err))
    {
        jw_event_dispatcher_destroy(client->dispatch);
        client->dispatch = NULL;
        goto jw_client_create_fail_label;
    }

    for (int index = 0; CLIENT_EVENTS[index] != NULL; index++)
    {
        if (!jw_event_dispatcher_create_event(client->dispatch,
                    CLIENT_EVENTS[index], NULL, err))
        {
            goto jw_client_create_fail_label;
        }
    }

    client->workq = workq;
    if (!_client_state_initialize(client, err))
    {
        goto jw_client_create_fail_label;
    }
    POP_CLIENT_NDC;
    *retclient = client;
    return true;

jw_client_create_fail_label:
    jw_client_destroy(client);
    POP_CLIENT_NDC;
    return false;
}

JABBERWERX_API void jw_client_destroy(jw_client *client)
{
    assert(client);

    PUSH_CLIENT_NDC;
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    client->destroying = true;

    if (client->stream)
    {
        // let the rest of destruction happen in the callback
        // client->_stream will be set to NULL in _stream_destroyed_cb
        jw_stream_destroy(client->stream);
    }
    else
    {
        // call the callback directly
        _stream_destroyed_cb_int(client);
    }
    POP_CLIENT_NDC;
}

static bool _reserve_config_item(jw_htable *config, const void *key, jw_err *err)
{
    JW_LOG_TRACE_FUNCTION("key='%s'", (const char *)key);

    if (jw_htable_get_node(config, key))
    {
        // already in the table
        return true;
    }

    return jw_htable_put(config, key, NULL, NULL, err);
}

// performs all fallible actions for jw_client_connect()
static bool _create_connect_data(
        jw_client *client, jw_htable *config, jw_tracker **ret_tracker,
        jw_jid **ret_jid, jw_stream **ret_stream, jw_err *err)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    jw_tracker *tracker = NULL;
    jw_jid     *jid     = NULL;
    jw_stream  *stream  = NULL;

    // prepare htable for later puts (turning them into infallible replaces)
    if (!_reserve_config_item(config, JW_STREAM_CONFIG_NAMESPACE,    err)
     || !_reserve_config_item(config, JW_STREAM_CONFIG_DOMAIN,       err)
     || !_reserve_config_item(config, JW_CLIENT_CONFIG_JID_CONTEXT,  err)
     || !_reserve_config_item(config, JW_CLIENT_CONFIG_SASL_FACTORY, err)
     || !_reserve_config_item(config, JW_CLIENT_CONFIG_RECONN_JID,   err))
    {
        jw_log_err(JW_LOG_WARN, err, "failed to reserve space in config");
        goto _create_connect_data_fail_label;
    }

    if (!jw_tracker_create(jw_htable_get(config, JW_STREAM_CONFIG_SELECTOR),
                           &tracker, err))
    {
        jw_log_err(JW_LOG_WARN, err, "failed to create tracker for client");
        goto _create_connect_data_fail_label;
    }

    if (!jw_event_bind(jw_event_dispatcher_get_event(
                          client->dispatch, JW_CLIENT_EVENT_BEFORE_IQ_RECEIVED),
                       jw_tracker_get_callback(), tracker, err))
    {
        jw_log_err(JW_LOG_WARN, err, "failed to bind tracker for client");
        goto _create_connect_data_fail_label;
    }

    // populates config with a jid context and sasl factory if necessary.  they
    // do not need to be cleaned up if this function fails.  they will be owned
    // by the config htable
    jid = _new_jid(config, NULL, err);
    if (!jid)
    {
        goto _create_connect_data_fail_label;
    }

    if (NULL == jw_htable_get(config, JW_CLIENT_CONFIG_SASL_FACTORY))
    {
        jw_sasl_factory *sasl_factory = NULL;
        jw_sasl_mech    *sasl_plain   = NULL;

        if (!jw_sasl_factory_create(config, &sasl_factory, err)
         || !jw_sasl_mech_plain_create(config, &sasl_plain, err)
         || !jw_sasl_factory_add_mech(sasl_factory, sasl_plain, err))
        {
            jw_log(JW_LOG_WARN,
                   "could not create or populate sasl factory for client");

            if (sasl_plain)
            {
                jw_sasl_mech_destroy(sasl_plain);
            }

            if (sasl_factory)
            {
                jw_sasl_factory_destroy(sasl_factory);
            }

            goto _create_connect_data_fail_label;
        }

        if (!jw_htable_put(config,
                           JW_CLIENT_CONFIG_SASL_FACTORY,
                           sasl_factory,
                           jw_sasl_factory_htable_cleaner,
                           err))
        {
            jw_log(JW_LOG_WARN,
                   "could not record sasl factory in client config");

            jw_sasl_factory_destroy(sasl_factory);
            goto _create_connect_data_fail_label;
        }
    }

    // create underlying stream
    const char *stream_type = jw_htable_get(config,
                                            JW_CLIENT_CONFIG_STREAM_TYPE);
    if (!stream_type ||
        jw_strncmp(stream_type,
                   JW_CLIENT_CONFIG_STREAM_TYPE_SOCKET,
                   strlen(JW_CLIENT_CONFIG_STREAM_TYPE_SOCKET)) == 0)
    {
        // check for port; default to JW_STREAM_CONFIG_PORT
        char *portstr = jw_htable_get(config, JW_STREAM_CONFIG_PORT);
        if (!portstr && !jw_htable_put(config, JW_STREAM_CONFIG_PORT,
                                       JW_CLIENT_DEFAULT_PORT, NULL, err))
        {
            goto _create_connect_data_fail_label;
        }

        if (!jw_stream_socket_create(client->workq, &stream, err))
        {
            goto _create_connect_data_fail_label;
        }
    }
    else if (0 == jw_strncmp(stream_type,
                             JW_CLIENT_CONFIG_STREAM_TYPE_BOSH,
                             strlen(JW_CLIENT_CONFIG_STREAM_TYPE_BOSH)))
    {
        if (!jw_stream_bosh_create(client->workq, &stream, err))
        {
            goto _create_connect_data_fail_label;
        }
    }
    else
    {
        JABBERWERX_ERROR(err, JW_ERR_INVALID_ARG);
        goto _create_connect_data_fail_label;
    }


    *ret_tracker = tracker;
    *ret_jid     = jid;
    *ret_stream  = stream;

    return true;

_create_connect_data_fail_label:
    if (stream)
    {
        jw_stream_destroy(stream);
    }
    if (jid)
    {
        jw_jid_destroy(jid);
    }
    if (tracker)
    {
        jw_event_unbind(jw_event_dispatcher_get_event(
                          client->dispatch, JW_CLIENT_EVENT_BEFORE_IQ_RECEIVED),
                        jw_tracker_get_callback());
        jw_tracker_destroy(tracker);
    }

    // destroy any reconnect timer items
    if (client->reconn.timer)
    {
        jw_workq_item_destroy(client->reconn.timer);
        client->reconn.timer = NULL;
    }

    return false;
}

/*
 * public API
 */

JABBERWERX_API bool jw_client_connect(jw_client *client,
                                      jw_htable *config,
                                      jw_err *err)
{
    assert(client);

    PUSH_CLIENT_NDC;
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    // check for required configuration
    if (!jw_htable_get(config, JW_CLIENT_CONFIG_USERJID))
    {
        jw_log(JW_LOG_WARN, "missing jid");
        JABBERWERX_ERROR(err, JW_ERR_INVALID_ARG);
        goto jw_client_connect_fail_label;
    }
    if (!jw_htable_get(config, JW_STREAM_CONFIG_SELECTOR))
    {
        jw_log(JW_LOG_WARN, "missing selector");
        JABBERWERX_ERROR(err, JW_ERR_INVALID_ARG);
        goto jw_client_connect_fail_label;
    }

    jw_tracker *tracker;
    jw_jid     *jid;
    jw_stream  *stream;

    if (!_create_connect_data(
            client, config, &tracker, &jid, &stream, err))
    {
        jw_log_err(JW_LOG_WARN, err, "failed to create connection data");
        goto jw_client_connect_fail_label;
    }

    if (client->stream)
    {
        //stop listening for the defunct but not destroyed stream
        _client_state_finalize(client);
        // Set client's state back to initial conditions
        if (!_client_state_initialize(client, err))
        {
            jw_log_err(JW_LOG_WARN,
                       err,
                       "client state object could not be initialized");
        }

        jw_stream_destroy(client->stream);
    }
    client->stream = stream;

    // Bind client's jw_state object to the newly created stream's events
    if (!_client_state_bind_stream(client, stream, err))
    {
        jw_log_err(JW_LOG_WARN, err, "Could not bind stream events to client states");
        goto jw_client_connect_fail_label;
    }
    if (!_client_state_change(client, FEAT_TLS, err))
    {
        goto jw_client_connect_fail_label;
    }

    if (client->jid)
    {
        jw_jid_destroy(client->jid);
    }
    client->jid = jid;

    if (client->tracker)
    {
        jw_tracker_destroy(client->tracker);
    }
    client->tracker = tracker;

    if (client->reconn.timer)
    {
        jw_workq_item_destroy(client->reconn.timer);
    }
    client->reconn.timer = NULL;

    if (client->mech_instance)
    {
        jw_sasl_mech_instance_destroy(client->mech_instance);
    }
    client->mech_instance = NULL;

    // populate and set config elements:
    // 1) force namespace "jabber:client" namespace
    // 2) enforce domain matches userjid domainpart
    if (!jw_htable_put(config, JW_STREAM_CONFIG_NAMESPACE,
                       JW_CLIENT_URI, NULL, err)
     || !jw_htable_put(config, JW_STREAM_CONFIG_DOMAIN,
                       (char *)jw_jid_get_domain(jid), NULL, err))
    {
        // should never happen since space has already been reserved
        jw_log_err(JW_LOG_ERROR, err,
                   "failed to replace element in config htable");
        assert(false);
    }
    // if reconnecting then do not reinit stream management state, current state
    // holds resume data
    if (!_reconn_reconnecting(client))
    {
        _stream_mgmt_state sm_state = &client->stream_mgmt_state;

        // reinit stream management state
        _clean_stream_mgmt_state(sm_state);

        uint32_t ack_threshold =
                (uintptr_t)jw_htable_get(config,
                                         JW_CLIENT_CONFIG_SM_ACK_REQUEST_THRESHOLD);
        sm_state->ack_request_threshold = (0 == ack_threshold) ?
                    JW_CLIENT_DEFAULT_SM_ACK_REQUEST_THRESHOLD : ack_threshold;

        if (!jw_timer_create(client->workq, &sm_state->ack_request_timer, err))
        {
            goto jw_client_connect_fail_label;
        }

        double dtime;
        if (!jw_utils_config_get_double(
                config,
                JW_CLIENT_CONFIG_SM_ACK_REQUEST_THRESHOLD_SECONDS,
                JW_CLIENT_DEFAULT_SM_ACK_REQUEST_THRESHOLD_SECONDS,
                &dtime,
                err))
        {
            jw_log_err(JW_LOG_WARN, err,
         "Could not convert JW_CLIENT_CONFIG_SM_ACK_REQUEST_THRESHOLD_SECONDS");
            dtime = JW_CLIENT_DEFAULT_SM_ACK_REQUEST_THRESHOLD_SECONDS;
        }
        jw_timer_set_inactivity_timeout(sm_state->ack_request_timer,
                                        jw_utils_dtoms(dtime));

        if (!jw_event_bind(
                    jw_timer_event(sm_state->ack_request_timer,
                                   JW_TIMER_EVENT_TIMEOUT),
                    _sm_r_timeout_handler, client, err)
         || !jw_event_bind(
                    jw_timer_event(sm_state->ack_request_timer,
                                   JW_TIMER_EVENT_ERROR),
                    _timeout_error_handler, client, err))
        {
            goto jw_client_connect_fail_label;
        }
    }
    if (!jw_stream_open(stream, config, err))
    {
        // "streamOpened" callback closes stream if it fails in authentication
        // or binding. "
        // streamClosed" callback updates client status and error
        // and triggers "clientStatusChanged" and "clientDisconnected".
        //
        // if this fails, we don't need to clean up since our object is entirely
        // consistent
        goto jw_client_connect_fail_label;
    }
    //change to connecting if not resuming
    if (client->status.cur_status == JW_CLIENT_DISCONNECTED)
    {
        _set_next_status(&client->status, JW_CLIENT_CONNECTING);
        _trigger_status_changed(client);
    }
    POP_CLIENT_NDC;
    return true;

jw_client_connect_fail_label:
    // does client needs to be returned to a pristine state here?
    // The client can be in many different states depending on the type of error
    POP_CLIENT_NDC;
    return false;
}

JABBERWERX_API void jw_client_disconnect(jw_client *client,
                                         jw_errcode disconnect_reason)
{
    assert(client);

    PUSH_CLIENT_NDC;
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    _reconn_cancel_timer(client);
    if (JW_CLIENT_DISCONNECTED  == client->status.cur_status ||
        JW_CLIENT_DISCONNECTING == client->status.cur_status)
    {
        jw_log(JW_LOG_DEBUG, "jw_client_disconnect already called; returning");
        goto jw_client_disconnect_done_label;
    }

    _set_next_status(&client->status, JW_CLIENT_DISCONNECTING);
    _trigger_status_changed(client);

    // "streamClosed" callback updates client status and error and
    // triggers "clientStatusChanged" and "clientDisconnected"
    jw_stream_close(client->stream, disconnect_reason);

jw_client_disconnect_done_label:
    POP_CLIENT_NDC;
}

JABBERWERX_API jw_workq* jw_client_get_workq(jw_client *client)
{
    JW_LOG_TRACE_FUNCTION("client=%p", (void *)client);

    assert(client);

    return client->workq;
}

JABBERWERX_API struct event_base* jw_client_get_selector(jw_client *client)
{
    JW_LOG_TRACE_FUNCTION("client=%p", (void *)client);

    assert(client);

    // get it from the workq, not the stream.  in the onDestroyed event, stream
    // doesn't exist, but workq always does
    return jw_workq_get_selector(client->workq);
}

JABBERWERX_API jw_client_statustype jw_client_get_status(jw_client *client)
{
    JW_LOG_TRACE_FUNCTION("client=%p", (void *)client);

    assert(client);
    return client->status.cur_status;
}

JABBERWERX_API jw_htable *jw_client_get_config(jw_client *client)
{
    JW_LOG_TRACE_FUNCTION("client=%p", (void *)client);

    assert(client);
    jw_stream *stream = client->stream;
    return stream ? jw_stream_get_config(stream) : NULL;
}

JABBERWERX_API jw_jid *jw_client_get_jid(jw_client *client)
{
    JW_LOG_TRACE_FUNCTION("client=%p", (void *)client);

    assert(client);
    if (jw_client_is_connected(client))
    {
        return client->jid;
    }
    return NULL;
}

JABBERWERX_API bool jw_client_is_connected(jw_client *client)
{
    JW_LOG_TRACE_FUNCTION("client=%p", (void *)client);

    assert(client);
    return jw_client_get_status(client) == JW_CLIENT_CONNECTED;
}

JABBERWERX_API bool jw_client_is_reconnect_pending(jw_client *client)
{
    JW_LOG_TRACE_FUNCTION("client=%p", (void *)client);

    assert(client);
    return NULL != client->reconn.timer || client->status.reconnecting;
}

JABBERWERX_API jw_event *jw_client_event(jw_client *client, const char *name)
{
    JW_LOG_TRACE_FUNCTION("client=%p", (void *)client);

    assert(client);
    assert(name != NULL && *name != '\0');

    return jw_event_dispatcher_get_event(client->dispatch, name);
}

JABBERWERX_API
jw_client_statustype jw_client_status_get_previous(jw_client_status *status)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(status);
    return status->prev_status;
}

JABBERWERX_API
jw_client_statustype jw_client_status_get_next(jw_client_status *status)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(status);
    return status->cur_status;
}

JABBERWERX_API jw_dom_node *jw_client_status_get_error(jw_client_status *status)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(status);
    return status->err_dom;
}

JABBERWERX_API bool jw_client_status_is_reconnect(jw_client_status *status)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(status);
    return status->reconnecting;
}

JABBERWERX_API jw_client_reconnect_statustype
jw_client_reconnect_get_status(jw_client_reconnect_status *status)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(status);
    return status->status;
}

JABBERWERX_API uint32_t
jw_client_reconnect_get_countdown(jw_client_reconnect_status *status)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(status);
    return status->countdown / MS_PER_SECOND;
}

JABBERWERX_API uint32_t
jw_client_reconnect_get_attempts(jw_client_reconnect_status *status)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(status);
    return status->attempts;
}

JABBERWERX_API bool jw_client_send_stanza(jw_client *client,
                                          jw_dom_node *stanza,
                                          jw_err *err)
{
    assert(client);
    assert(stanza);

    PUSH_CLIENT_NDC;
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    jw_err _err;
    if (NULL == err)
    {
        // ensure err is non-null for the call to _close_on_error
        err = &_err;
    }

    // if not in connected state, return INVALID_STATE error
    if (JW_CLIENT_CONNECTED != client->status.cur_status)
    {
        jw_log(JW_LOG_WARN, "client is not connected; cannot send stanza");
        JABBERWERX_ERROR(err, JW_ERR_INVALID_STATE);
        goto jw_client_send_stanza_fail_label;
    }

    // get appropriate "before" event according to stanza type
    const char * ename = jw_dom_get_ename(stanza);
    const char * eventName;
    if (0 == strcmp(JW_CLIENT_PRESENCE, ename))
    {
        eventName = JW_CLIENT_EVENT_BEFORE_PRESENCE_SENT;
    }
    else if (0 == strcmp(JW_CLIENT_MESSAGE, ename))
    {
        eventName = JW_CLIENT_EVENT_BEFORE_MESSAGE_SENT;
    }
    else if (0 == strcmp(JW_CLIENT_IQ, ename))
    {
        eventName = JW_CLIENT_EVENT_BEFORE_IQ_SENT;
    }
    else
    {
        jw_log_dom(JW_LOG_WARN, stanza, "unrecognized stanza type: ");
        JABBERWERX_ERROR(err, JW_ERR_INVALID_ARG);
        goto jw_client_send_stanza_fail_label;
    }

    jw_event *beforeEvent = jw_event_dispatcher_get_event(
                                    client->dispatch, eventName);

    // send off "before" event
    if (!jw_event_trigger(beforeEvent, stanza, _send_stanza_cb, client, err))
    {
        // err is set by jw_event_trigger
        goto jw_client_send_stanza_fail_label;
    }

    POP_CLIENT_NDC;
    return true;

jw_client_send_stanza_fail_label:
    // destroy stanza context and return error (err is already set)
    jw_dom_context_destroy(jw_dom_get_context(stanza));
    _close_on_error(client, err);
    POP_CLIENT_NDC;

    return false;
}

JABBERWERX_API bool jw_client_track_iq(jw_client *client,
                                       jw_dom_node *iq,
                                       jw_tracker_cb_func cb,
                                       void *user_data,
                                       uint32_t timeout_sec,
                                       jw_err *err)
{
    assert(client);
    assert(iq);
    assert(cb);

    PUSH_CLIENT_NDC;
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    // if not in connected state, return INVALID_STATE error
    if (JW_CLIENT_CONNECTED != client->status.cur_status)
    {
        JABBERWERX_ERROR(err, JW_ERR_INVALID_STATE);
        goto track_stanza_fail_cleanup_label;
    }

    const char *ename = jw_dom_get_ename(iq);
    if (jw_strcmp(JW_CLIENT_IQ, ename))
    {
        JABBERWERX_ERROR(err, JW_ERR_INVALID_ARG);
        goto track_stanza_fail_cleanup_label;
    }

    assert(client->tracker);
    if (!jw_tracker_track(client->tracker,
                          iq,
                          cb,
                          user_data,
                          timeout_sec,
                          err))
    {
        goto track_stanza_fail_cleanup_label;
    }

    if (!jw_client_send_stanza(client, iq, err))
    {
        // send_stanza owns the iq now.  Do not clean up.
        goto track_stanza_fail_label;
    }

    POP_CLIENT_NDC;
    return true;

track_stanza_fail_cleanup_label:
    // destroy stanza context and return error (err is already set)
    jw_dom_context_destroy(jw_dom_get_context(iq));

track_stanza_fail_label:
    POP_CLIENT_NDC;
    // no need to close here.  if it's a bad state, or a bad stanza, that doesn't
    // invalidatae the stream.
    return false;
}
