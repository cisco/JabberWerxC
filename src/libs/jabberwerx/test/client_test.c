/**
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

#define _GNU_SOURCE
#include "echosrv.h"
#include "stanza_defines.h"
#include "test_utils.h"
#include "../src/include/client_int.h"
#include "../src/include/stream_int.h"

#include <fct.h>
#include <jabberwerx/util/log.h>
#include <jabberwerx/util/mem.h>
#include <jabberwerx/client.h>
#include <jabberwerx/util/str.h>
#include <limits.h>
#include <event2/buffer.h>
#include <event2/event.h>


// JIDs used to test binding
#define CLIENT_JID_FULL "client-user@localhost/client-resource"
#define ECHOSRV_JID_FULL "echo-user@localhost/echosrv-resource"
#define ECHOSRV_JID_CLIENT_RESOURCE "echo-user@localhost/client-resource"
#define CLIENT_TEST_JID "CLIENT_TEST_JID"

typedef enum
{
    START,
    CONNECTED,
    STANZA_SENT,
    STANZA_RECEIVED,
    DISCONNECTED,
    PAUSED,
    STATUS_CHANGED,
    RECONN_STATUS_CHANGED,
    DESTROYED
} testStateType;

static testStateType _clientState = START;
static bool _fail = false;

/**
 * Set of client connect event handlers
 */
typedef struct {
    jw_event_notify_callback _clientConnected;
    jw_event_notify_callback _clientDisconnected;
    jw_event_notify_callback _clientStatusChanged;
    jw_event_notify_callback _clientReconnStatusChanged;
    jw_event_notify_callback _clientDestroyed;
    jw_event_notify_callback _clientPresSent;
    jw_event_notify_callback _clientPresRecv;
} testClientConnectEvents;

/**
 * one FCT client test's data, passed through event handlers
 */
typedef struct  {
    testStateType      state;
    bool               failed;
    uint32_t           counter;
    jw_dom_node  *error;
    struct event_base *evbase;
    struct event      *failsafeEvent;
    jw_test_echosrv         echosrv;
    jw_htable    *config;
    jw_workq     *workq;
} testDataType;


static testDataType *_newTestData()
{
    testDataType *ret = jw_data_malloc(sizeof(testDataType));
    if (ret)
    {
        memset(ret, 0, sizeof(testDataType));
        ret->state = START;
        ret->failed = false;
        if (!_test_init(&ret->evbase,
                        &ret->failsafeEvent,
                        &ret->config,
                        &ret->workq,
                        &ret->echosrv))
        {
            jw_data_free(ret);
            ret = NULL;
        }
    }
    return ret;
}

static void _finalizeTestData(testDataType *data)
{
    if (data->error)
    {
        jw_dom_context_destroy(jw_dom_get_context(data->error));
        data->error = NULL;
    }
    _test_cleanup(data->evbase,
              data->failsafeEvent,
              data->config,
              data->workq,
              data->echosrv);
    jw_data_free(data);
}

const char *getStatusString(jw_client_statustype s)
{
    switch(s)
    {
    case JW_CLIENT_DISCONNECTED:  return "DISCONNECTED";
    case JW_CLIENT_CONNECTING:    return "CONNECTING";
    case JW_CLIENT_CONNECTED:     return "CONNECTED";
    case JW_CLIENT_DISCONNECTING: return "DISCONNECTING";
    }
    return "invalid";
}

static inline jw_dom_node *_new_stream_error(jw_dom_ctx *ctx,
                                                  const char *err_name)
{
    jw_dom_node *ret, *child;
    jw_dom_ctx *tctx = ctx;
    if (!tctx && !jw_dom_context_create(&tctx, NULL))
    {
        return NULL;
    }
    if (!jw_dom_element_create(tctx, JW_STREAM_ENAME_ERROR, &ret, NULL)
         || !jw_dom_element_create(tctx, err_name, &child, NULL)
         || !jw_dom_add_child(ret, child, NULL))
    {
        ret = NULL;
        //created context if needed, cleanup
        if (!ctx)
        {
            jw_dom_context_destroy(tctx);
        }
    }
    return ret;
}

static jw_dom_node *_new_test_message(jw_client *client,
                                           uint32_t msgcount,
                                           const char *extra_body)
{
    jw_err err;
    char *counterStr = NULL;
    jw_dom_ctx  *domCtx = NULL;

    if (!jw_dom_context_create(&domCtx, &err))
    {
        jw_log_err(JW_LOG_WARN, &err, "failed to create message DOM context");
        return NULL;
    }

    jw_jid *jid = jw_client_get_jid(client);
    if (NULL == jid)
    {
        jw_log(JW_LOG_WARN, "message jid from client is NULL");
        goto _new_test_message_except;
    }

    if (!jw_pool_malloc(jw_dom_context_get_pool(domCtx),
                        UINT32_MAX_WIDTH + jw_strlen(extra_body) + 2,
                        (void **)(&counterStr), &err))
    {
        jw_log_err(JW_LOG_WARN, &err, "failed to allocate memory for counter");
        goto _new_test_message_except;
    }

    // decrement the countdown and use it to identify the message
    int ret = snprintf(counterStr, UINT32_MAX_WIDTH, "%u%s", msgcount, extra_body ? extra_body : "");
    if (0 >= ret || UINT32_MAX_WIDTH <= (uint32_t)ret)
    {
        jw_log(JW_LOG_ERROR, "unknown error stringifying counter");
        goto _new_test_message_except;
    }

    jw_dom_node *stanza   = NULL;
    jw_dom_node *body     = NULL;
    jw_dom_node *bodyText = NULL;

    if (!jw_dom_element_create(domCtx, "{jabber:client}message", &stanza, &err)
     || !jw_dom_set_attribute(stanza, "{}id", counterStr, &err)
     || !jw_dom_set_attribute(stanza, "{}from", jw_jid_get_bare(jid), &err)
     || !jw_dom_set_attribute(stanza, "{}to", jw_jid_get_full(jid), &err)
     || !jw_dom_set_attribute(stanza, "{}type", "chat", &err)
     || !jw_dom_element_create(domCtx, "{jabber:client}body", &body, &err)
     || !jw_dom_text_create(domCtx, counterStr, &bodyText, &err)
     || !jw_dom_add_child(body, bodyText, &err)
     || !jw_dom_add_child(stanza, body, &err))
    {
        jw_log_err(JW_LOG_WARN, &err, "failed to create stanza");
        goto _new_test_message_except;
    }
    return stanza;

_new_test_message_except:
    jw_dom_context_destroy(domCtx);
    return NULL;
}

static bool _bindEvent(jw_client *client, const char *eventName,
                       jw_event_notify_callback cb, void *arg)
{
    return jw_event_bind(jw_client_event(client, eventName), cb, arg, NULL);
}

static void _unbindEvent(jw_client *client, const char *eventName,
                         jw_event_notify_callback cb)
{
    jw_event_unbind(jw_client_event(client, eventName), cb);
}

static bool _bindConnectEvents(jw_client *client,
                               testClientConnectEvents *callbacks,
                               testDataType *data)
{
    bool ret = true;
    if (callbacks->_clientConnected)
    {
        ret = _bindEvent(client, JW_CLIENT_EVENT_CONNECTED, callbacks->_clientConnected, data);
    }
    if (ret && callbacks->_clientDisconnected)
    {
        ret = _bindEvent(client, JW_CLIENT_EVENT_DISCONNECTED, callbacks->_clientDisconnected, data);
    }
    if (ret && callbacks->_clientDestroyed)
    {
        ret = _bindEvent(client, JW_CLIENT_EVENT_DESTROYED,    callbacks->_clientDestroyed, data);
    }
    if (ret && callbacks->_clientStatusChanged)
    {
        ret = _bindEvent(client, JW_CLIENT_EVENT_STATUSCHANGED, callbacks->_clientStatusChanged, data);
    }
    if (ret && callbacks->_clientReconnStatusChanged)
    {
        ret = _bindEvent(client, JW_CLIENT_EVENT_RECONNECT_STATUSCHANGED, callbacks->_clientReconnStatusChanged, data);
    }
    if (ret && callbacks->_clientPresRecv)
    {
        ret = _bindEvent(client, JW_CLIENT_EVENT_PRESENCE_RECEIVED, callbacks->_clientPresRecv, data);
    }
    if (ret && callbacks->_clientPresSent)
    {
        ret = _bindEvent(client, JW_CLIENT_EVENT_PRESENCE_SENT, callbacks->_clientPresSent, data);
    }
    return ret;
}

static void _unbindConnectEvents(jw_client *client,
                                 testClientConnectEvents *callbacks)
{
    if (callbacks->_clientConnected)
    {
        _unbindEvent(client, JW_CLIENT_EVENT_CONNECTED, callbacks->_clientConnected);
    }
    if (callbacks->_clientDisconnected)
    {
        _unbindEvent(client, JW_CLIENT_EVENT_DISCONNECTED, callbacks->_clientDisconnected);
    }
    if (callbacks->_clientDestroyed)
    {
        _unbindEvent(client, JW_CLIENT_EVENT_DESTROYED, callbacks->_clientDestroyed);
    }
    if (callbacks->_clientStatusChanged)
    {
        _unbindEvent(client, JW_CLIENT_EVENT_STATUSCHANGED, callbacks->_clientStatusChanged);
    }
    if (callbacks->_clientReconnStatusChanged)
    {
        _unbindEvent(client, JW_CLIENT_EVENT_RECONNECT_STATUSCHANGED, callbacks->_clientReconnStatusChanged);
    }
    if (callbacks->_clientPresRecv)
    {
        _unbindEvent(client, JW_CLIENT_EVENT_PRESENCE_RECEIVED, callbacks->_clientPresRecv);
    }
    if (callbacks->_clientPresSent)
    {
        _unbindEvent(client, JW_CLIENT_EVENT_PRESENCE_SENT, callbacks->_clientPresSent);
    }
}

/**
 * Event callback that sets a failed flag and terminates test if called.
 * Used to ensure specific events were not fired during a test.
 */
static void _failIfCalled(jw_event_data event, void *arg)
{
    UNUSED_PARAM(event);
    UNUSED_PARAM(arg);

    jw_log(JW_LOG_WARN, "unexpected call to _failIfCalled during event %s", event->name);
    _fail = true;
    event_base_loopbreak(jw_client_get_selector((jw_client *)event->source));
}

/**
 * clientConnected event handler. Fails and terminates connection if not called
 * at the proper time (test state == start)
 * Caches client data in config for testing after connection has finished
 */
static void _onConnected(jw_event_data event, void *arg)
{
    UNUSED_PARAM(arg);

    jw_client *client = event->source;

    if (_clientState != START)
    {
        jw_log(JW_LOG_WARN, "unexpected call to _onConnected");
        _fail = true;
        event_base_loopbreak(jw_client_get_selector(client));
        return;
    }
    _clientState = CONNECTED;

    // save client's jid in config so it can be tested later
    jw_htable_put(jw_client_get_config(client),
                  CLIENT_TEST_JID,
                  (void *)jw_jid_get_full(jw_client_get_jid(client)),
                  NULL, NULL);

    // jw_client will send a presence stanza
    jw_log(JW_LOG_DEBUG, "connected");
}

/**
 * clientDisconnected event handler, fails if event was not received in the
 * proper order, terminates the evbase loop to stop events and allow tests
 * to finish
 */
static void _onDisconnected(jw_event_data event, void *arg)
{
    UNUSED_PARAM(arg);

    jw_client *client = event->source;

    if (_clientState != STANZA_RECEIVED)
    {
        jw_log(JW_LOG_WARN, "unexpected call to _onDisconnected");
        _fail = true;
        event_base_loopbreak(jw_client_get_selector(client));
        return;
    }
    _clientState = DISCONNECTED;

    jw_log(JW_LOG_DEBUG, "client disconnected");

    event_base_loopbreak(jw_client_get_selector(client));
}

/**
 * clientStatusChanged event handler
 */
static void _onStatusChanged(jw_event_data event, void *arg)
{
    UNUSED_PARAM(arg);

    jw_client *client = event->source;
    jw_client_status *status = event->data;

    jw_client_statustype prev = jw_client_status_get_previous(status);
    jw_client_statustype cur = jw_client_status_get_next(status);

    if (prev == cur)
    {
        jw_log(JW_LOG_WARN, "unexpected call to _onStatusChanged");
        _fail = true;
        event_base_loopbreak(jw_client_get_selector(client));
        return;
    }

    if (jw_client_is_connected(client))
    {
        jw_log(JW_LOG_INFO, "Client connected as jid: %s",
                                    jw_jid_get_full(jw_client_get_jid(client)));
    }
    else
    {
        jw_log(JW_LOG_INFO, "Client jid unknown");
    }
    jw_log(JW_LOG_WARN, "Client status changed: %s --> %s",
                                   getStatusString(prev), getStatusString(cur));
}

/**
 * clientDestroyed event handler
 */
static void _onDestroyed(jw_event_data event, void *arg)
{
    UNUSED_PARAM(event);
    UNUSED_PARAM(arg);

    _clientState = DESTROYED;
    jw_log(JW_LOG_DEBUG, "client destroyed");
}
/**
 * stanzaSent event handler
 */

static void _onStanzaSent(jw_event_data event, void *arg)
{
    UNUSED_PARAM(arg);

    if (_clientState != CONNECTED)
    {
        jw_log(JW_LOG_WARN, "unexpected call to _onStanzaSent");
        _fail = true;
        event_base_loopbreak(jw_client_get_selector(event->source));
        return;
    }
    _clientState = STANZA_SENT;
}

/**
 * stanzaReceived event handler
 */

static void _onStanzaRecv(jw_event_data event, void *arg)
{
    jw_err err;
    jw_client *client = event->source;
    struct event_base * evbase = jw_client_get_selector(client);

    if (STANZA_SENT != _clientState && STANZA_RECEIVED != _clientState)
    {
        jw_log(JW_LOG_WARN, "unexpected call to _onStanzaRecv");
        goto _onStanzaRecv_fail_label;
    }
    _clientState = STANZA_RECEIVED;

    uint32_t *countdown = (uint32_t *)arg;
    if (NULL == countdown || 0 == *countdown)
    {
        jw_log(JW_LOG_DEBUG, "final stanza received; closing down the client");
        jw_client_disconnect(client, JW_ERR_NONE);
        return;
    }

    // send another message
    jw_jid *jid = jw_client_get_jid(client);
    if (NULL == jid)
    {
        jw_log(JW_LOG_WARN, "jid is NULL");
        goto _onStanzaRecv_fail_label;
    }

    jw_dom_ctx *domCtx = NULL;
    if (!jw_dom_context_create(&domCtx, &err))
    {
        jw_log_err(JW_LOG_WARN, &err, "jw_dom_context_create failed");
        goto _onStanzaRecv_fail_label;
    }

    char *counterStr;
    if (!jw_pool_malloc(jw_dom_context_get_pool(domCtx),
                        UINT32_MAX_WIDTH, (void **)(&counterStr), &err))
    {
        jw_log_err(JW_LOG_WARN, &err, "failed to allocate memory for counter");
        jw_dom_context_destroy(domCtx);
        goto _onStanzaRecv_fail_label;
    }

    // decrement the countdown and use it to identify the message
    int ret = snprintf(counterStr, UINT32_MAX_WIDTH, "%u", --*countdown);
    if (0 >= ret || UINT32_MAX_WIDTH <= (uint32_t)ret)
    {
        jw_log(JW_LOG_ERROR, "unknown error stringifying counter");
        assert(false);
    }

    jw_dom_node *stanza   = NULL;
    jw_dom_node *body     = NULL;
    jw_dom_node *bodyText = NULL;
    if (!jw_dom_element_create(domCtx, "{jabber:client}message", &stanza, &err)
     || !jw_dom_set_attribute(stanza, "{}id", "test", &err)
     || !jw_dom_set_attribute(stanza, "{}from", jw_jid_get_bare(jid), &err)
     || !jw_dom_set_attribute(stanza, "{}to", jw_jid_get_full(jid), &err)
     || !jw_dom_set_attribute(stanza, "{}type", "chat", &err)
     || !jw_dom_element_create(domCtx, "{jabber:client}body", &body, &err)
     || !jw_dom_text_create(domCtx, counterStr, &bodyText, &err)
     || !jw_dom_add_child(body, bodyText, &err)
     || !jw_dom_add_child(stanza, body, &err))
    {
        jw_log_err(JW_LOG_WARN, &err, "failed to create stanza");
        jw_dom_context_destroy(domCtx);
        goto _onStanzaRecv_fail_label;
    }

    jw_log(JW_LOG_DEBUG, "sending stanza (countdown value: %u)", *countdown);
    if (!jw_client_send_stanza(client, stanza, &err))
    {
        jw_log_err(JW_LOG_WARN, &err, "jw_client_send_stanza failed");
        _fail = true;
        event_base_loopbreak(evbase);
    }

    return;

_onStanzaRecv_fail_label:
    _fail = true;
    event_base_loopbreak(evbase);
}

static void _onReconConnected(jw_event_data event, void *arg)
{
    UNUSED_PARAM(arg);

    jw_log(JW_LOG_WARN, "entered _onReconConnected");
    jw_client *client = event->source;

    if (((testDataType *)arg)->state != START)
    {
        jw_log(JW_LOG_WARN, "unexpected call to _onConnected");
        ((testDataType *)arg)->failed = true;
        event_base_loopbreak(jw_client_get_selector(client));
        return;
    }
    ((testDataType *)arg)->state = CONNECTED;

    // save client's jid in config so it can be tested later
    jw_htable_put(jw_client_get_config(client),
                  CLIENT_TEST_JID,
                  (void *)jw_jid_get_full(jw_client_get_jid(client)),
                  NULL, NULL);

    // jw_client will send a presence stanza
    jw_log(JW_LOG_DEBUG, "connected");
}

static void _onReconDisconnect(jw_event_data event, void *arg)
    {
    UNUSED_PARAM(arg);
    jw_log(JW_LOG_WARN, "entered _onReconDisconnect");

    jw_client *client = event->source;
    if (!jw_client_is_reconnect_pending(client))
    {
        ((testDataType *)arg)->state = DISCONNECTED;
        jw_log(JW_LOG_WARN, "Disconnected without pending reconnect, exiting test.");
        event_base_loopbreak(jw_client_get_selector(client));
    }
    else
    {
        ((testDataType *)arg)->state = PAUSED;
        jw_log(JW_LOG_WARN, "Disconnected, waiting for reconnect attempt.");
    }
}


static void _onReconStatus(jw_event_data event, void *arg)
{
    UNUSED_PARAM(arg);

    jw_log(JW_LOG_WARN, "entered _onReconStatus");
    //jw_client client = event->source;
    jw_client_reconnect_status *status = event->data;
    const char* status_type;

    ((testDataType *)arg)->state = RECONN_STATUS_CHANGED;
    switch(jw_client_reconnect_get_status(status))
    {
        case JW_CLIENT_RECONNECT_PENDING: status_type = "pending";break;
        case JW_CLIENT_RECONNECT_STARTING: status_type = "starting";break;
        case JW_CLIENT_RECONNECT_CANCELED: status_type = "canceled";break;
        default: status_type = "unknown";
    }

    jw_log(JW_LOG_WARN, "_onReconnectStatus - type: %s, attempts: %d, countdown %d",
             status_type,
             jw_client_reconnect_get_attempts(status),
             jw_client_reconnect_get_countdown(status));
}

static void _onReconClientStatus(jw_event_data event, void *arg)
{
    UNUSED_PARAM(arg);

    jw_log(JW_LOG_WARN, "entered _onReconClientStatus");
    jw_client *client = event->source;
    jw_client_status *status = event->data;

    jw_client_statustype prev = jw_client_status_get_previous(status);
    jw_client_statustype cur = jw_client_status_get_next(status);

    if (prev == cur)
    {
        jw_log(JW_LOG_WARN, "unexpected call to _onReconClientStatus");
        ((testDataType *)arg)->failed = true;
        event_base_loopbreak(jw_client_get_selector(client));
        return;
}

    if (jw_client_is_connected(client))
    {
        jw_log(JW_LOG_INFO, "Client connected as jid: %s",
                                    jw_jid_get_full(jw_client_get_jid(client)));
    }
    else
    {
        jw_log(JW_LOG_INFO, "Client jid unknown");
    }
    jw_log(JW_LOG_WARN, "Client status changed: %s --> %s",
                                   getStatusString(prev), getStatusString(cur));
}

/**
 * clientDestroyed event handler
 */
static void _onReconDestroyed(jw_event_data event, void *arg)
{
    UNUSED_PARAM(event);

    jw_log(JW_LOG_WARN, "entered _onReconDestroyed");
    ((testDataType *)arg)->state = DESTROYED;
    jw_log(JW_LOG_DEBUG, "client destroyed");
}

static void _reconOnStanzaRecv(jw_event_data event, void *arg)
{
    jw_err err;
    jw_client *client = event->source;
    struct event_base * evbase = jw_client_get_selector(client);
    testDataType *data = ((testDataType *)arg);
    jw_dom_node *stanza = NULL;

    jw_log(JW_LOG_WARN, "entered _reconOnStanzaRecv");

    if (0 == data->counter)
    {
        jw_log(JW_LOG_DEBUG, "final stanza received; closing down the client");
        //force a disconnection if given an error use
        if (data->error)
        {
            jw_log(JW_LOG_DEBUG, "found error, adding echosrv close");

            jw_dom_node *stanza =
                    _new_test_message(client, data->counter, NULL);
            if (!stanza
             || !_jw_test_echosrv_core_add_command(
                               stanza, JW_ECHOSRV_CMD_CLOSE, data->error, NULL))
            {
                jw_log(JW_LOG_WARN, "could not create reply stanza");
                goto _reconOnStanzaRecv_fail_label;
            }

            jw_dom_context_destroy(jw_dom_get_context(data->error));
            data->error = NULL;

            if (!jw_client_send_stanza(client, stanza, &err))
            {
                jw_log_err(JW_LOG_WARN, &err, "jw_client_send_stanza failed");
                goto _reconOnStanzaRecv_fail_label;
            }
            return;
        }
        else
        {
            jw_log(JW_LOG_WARN, "no error graceful disconnect");
            jw_client_disconnect(client, JW_ERR_NONE);
            return;
        }
    }
    else
    {
        --data->counter;
    }

    if (!stanza)
    {
        stanza = _new_test_message(client, data->counter, NULL);
        if (!stanza)
        {
            jw_log(JW_LOG_WARN, "could not create reply stanza");
            goto _reconOnStanzaRecv_fail_label;
        }
    }
    if (!jw_client_send_stanza(client, stanza, &err))
    {
        jw_log_err(JW_LOG_WARN, &err, "jw_client_send_stanza failed");
        goto _reconOnStanzaRecv_fail_label;
    }

    return;

_reconOnStanzaRecv_fail_label:
    ((testDataType *)arg)->failed = true;
    event_base_loopbreak(evbase);
}

testClientConnectEvents RECONNECT_CALLBACKS = {_onReconConnected,
                                               _onReconDisconnect,
                                               _onReconClientStatus,
                                               _onReconStatus,
                                               _onReconDestroyed,
                                               NULL,
                                               _reconOnStanzaRecv};


static void _receivedHandledTestCallback(jw_event_data event, void *arg)
{
    UNUSED_PARAM(arg);

    jw_client *client = event->source;
    struct event_base *evbase = jw_client_get_selector(client);

    event->handled = true;

    if (_clientState != STANZA_SENT)
    {
        jw_log(JW_LOG_WARN, "unexpected call to _receivedHandledTestCallback");
        _fail = true;
        event_base_loopbreak(evbase);
        return;
    }

    // rebind original handler and realign state
    _unbindEvent(client, JW_CLIENT_EVENT_BEFORE_PRESENCE_RECEIVED, _receivedHandledTestCallback);
    _unbindEvent(client, JW_CLIENT_EVENT_PRESENCE_RECEIVED, _failIfCalled);
    _bindEvent(client, JW_CLIENT_EVENT_PRESENCE_RECEIVED, _onStanzaRecv, NULL);
    _clientState = CONNECTED;
    // send another presence stanza
    jw_dom_ctx *domCtx = NULL;
    jw_err err;
    jw_dom_node *presenceStanza = NULL;
    if (!jw_dom_context_create(&domCtx, &err))
    {
        jw_log_err(JW_LOG_ERROR, &err, "could not create dom context");
        _fail = true;
        event_base_loopbreak(evbase);
        return;
    }
    if (!jw_dom_element_create(domCtx, XMPP_CLIENT_PRESENCE,
                               &presenceStanza, &err))
    {
        jw_dom_context_destroy(domCtx);
        jw_log_err(JW_LOG_ERROR, &err, "could not create presence stanza");
        _fail = true;
        event_base_loopbreak(evbase);
        return;
    }
    if (!jw_client_send_stanza(client, presenceStanza, &err))
    {
        jw_log_err(JW_LOG_ERROR, &err, "could not send presence stanza");
        _fail = true;
        event_base_loopbreak(evbase);
        return;
    }
}

static bool _oom_test(jw_err *err)
{
    jw_client    *client        = NULL;
    struct event_base *evbase        = NULL;
    struct event      *failsafeEvent = NULL;
    jw_test_echosrv    echosrv       = NULL;
    jw_htable    *config        = NULL;
    jw_workq     *workq         = NULL;

    bool retval = false;

    jw_log(JW_LOG_DEBUG, "starting _oom_test");

    if (!_test_init(&evbase, &failsafeEvent, &config, &workq, &echosrv)
     || !jw_client_create(workq, &client, NULL))
    {
        goto _oom_test_done_label;
    }

    if (!_bindEvent(client, JW_CLIENT_EVENT_CONNECTED,         _onConnected,    NULL)
     || !_bindEvent(client, JW_CLIENT_EVENT_DISCONNECTED,      _onDisconnected, NULL)
     || !_bindEvent(client, JW_CLIENT_EVENT_DESTROYED,         _onDestroyed,    NULL)
     || !_bindEvent(client, JW_CLIENT_EVENT_PRESENCE_SENT,     _onStanzaSent,   NULL)
     || !_bindEvent(client, JW_CLIENT_EVENT_PRESENCE_RECEIVED, _onStanzaRecv,   NULL))
    {
        goto _oom_test_done_label;
    }

    if (!jw_client_connect(client, config, err))
    {
        goto _oom_test_done_label;
    }

    _clientState = START;
    _fail        = false;
    event_base_dispatch(evbase);
    if (DISCONNECTED != _clientState || _fail || _test_get_timed_out())
    {
        goto _oom_test_done_label;
    }

    retval = true;

_oom_test_done_label:
    if (client)
    {
        jw_client_destroy(client);
        event_base_loop(evbase, EVLOOP_NONBLOCK);
    }
    if (_clientState != DESTROYED)
    {
        retval = false;
    }

    _test_cleanup(evbase, failsafeEvent, config, workq, echosrv);

    return retval;
}


static jw_loglevel _initlevel;
FCTMF_FIXTURE_SUITE_BGN(client_test)
{
    FCT_SETUP_BGN()
    {
        _initlevel = jw_log_get_level();
        _test_init_counting_memory_funcs();
    } FCT_SETUP_END()

    FCT_TEARDOWN_BGN()
    {
        fct_chk_eq_int(_test_get_free_count(), _test_get_malloc_count());
        if (_test_get_free_count() != _test_get_malloc_count())
        {
            jw_log(JW_LOG_ERROR,
                   "mem leak detected in %s: mallocCnt=%d; freeCnt=%d",
                   fctkern_ptr__->ns.curr_test_name,
                   _test_get_malloc_count(), _test_get_free_count());
        }
        _test_uninit_counting_memory_funcs();
        jw_log_set_level(_initlevel);
    } FCT_TEARDOWN_END()

    FCT_TEST_BGN(verify_client_config)
    {
        //jw_log_set_level(JW_LOG_TRACE);

        jw_client    *client;
        testDataType      *data;
        jw_err             err;

        data = _newTestData();
        fct_req(NULL != data);

        fct_req(jw_client_create(data->workq, &client, NULL));

        _bindEvent(client, JW_CLIENT_EVENT_CONNECTED,         _failIfCalled, data);
        _bindEvent(client, JW_CLIENT_EVENT_DISCONNECTED,      _failIfCalled, data);
        _bindEvent(client, JW_CLIENT_EVENT_DESTROYED,         _onDestroyed,  data);
        _bindEvent(client, JW_CLIENT_EVENT_PRESENCE_SENT,     _failIfCalled, data);
        _bindEvent(client, JW_CLIENT_EVENT_PRESENCE_RECEIVED, _failIfCalled, data);


        // ensure missing required parameters cause connect to fail
        char *reqParams[] = {
            JW_CLIENT_CONFIG_USERJID,
            JW_STREAM_CONFIG_SELECTOR,
            NULL
        };

        // TODO: check for incorrect options, not just missing ones
        for (int reqParamIdx = 0; reqParams[reqParamIdx]; ++reqParamIdx)
        {
            jw_htable_remove(data->config, reqParams[reqParamIdx]);
            fct_req(!jw_client_connect(client, data->config, &err));
            fct_chk_eq_int(JW_ERR_INVALID_ARG, err.code);
            fct_req(_test_init_config(data->config, data->evbase, data->echosrv));
        }

        jw_client_destroy(client);

        event_base_loop(data->evbase, EVLOOP_NONBLOCK);
        fct_chk(_clientState == DESTROYED);
        fct_chk(!_fail);
        _finalizeTestData(data);
    } FCT_TEST_END()

    FCT_TEST_BGN(basic_client)
    {
        //jw_log_set_level(JW_LOG_TRACE);

        jw_client    *client;
        struct event_base *evbase;
        struct event      *failsafeEvent;
        jw_test_echosrv    echosrv;
        jw_htable    *config;
        jw_workq     *workq;

        fct_req(_test_init(&evbase, &failsafeEvent, &config, &workq, &echosrv));
        fct_req(jw_client_create(workq, &client, NULL));

        _bindEvent(client, JW_CLIENT_EVENT_CONNECTED,         _onConnected,    NULL);
        _bindEvent(client, JW_CLIENT_EVENT_DISCONNECTED,      _onDisconnected, NULL);
        _bindEvent(client, JW_CLIENT_EVENT_DESTROYED,         _onDestroyed,    NULL);
        _bindEvent(client, JW_CLIENT_EVENT_PRESENCE_SENT,     _onStanzaSent,   NULL);
        _bindEvent(client, JW_CLIENT_EVENT_PRESENCE_RECEIVED, _onStanzaRecv,   NULL);

        fct_chk(jw_client_connect(client, config, NULL));

        // get things going
        _clientState = START;
        _fail        = false;
        event_base_dispatch(evbase);
        fct_req(!_test_get_timed_out());
        fct_chk(_clientState == DISCONNECTED);
        fct_chk(!_fail);

        jw_client_destroy(client);
        event_base_loop(evbase, EVLOOP_NONBLOCK);
        fct_chk(_clientState == DESTROYED);

        _test_cleanup(evbase, failsafeEvent, config, workq, echosrv);
    } FCT_TEST_END()

    FCT_TEST_BGN(basic_client_oom)
    {
        //jw_log_set_level(JW_LOG_TRACE);

        // have to pass NULL for the err object since otherwise the OOM macros
        // will check to ensure that the error code is always NO_MEMORY, which
        // in this case will only happen if the failure occurred on the client
        // side of the connection (echosrv can also fail independently).
        OOM_RECORD_ALLOCS(_oom_test(NULL));

        // remove this line when the mem leaks and timeouts are fixed
        oom_get_data()->failureAttempts = 50;

        bool breaknext = false;
        OOM_TEST_INIT();
        if (breaknext)
        {
            fct_req(false);
        }
        if (_test_get_malloc_count() != _test_get_free_count()
         || _test_get_timed_out())
        {
            jw_log(JW_LOG_ERROR, "memory leak or timeout at attempt: %d;"
                  " enable the TRACE log level and rerun to debug", _oom_idx+1);
            --_oom_idx;
            //jw_log_set_level(JW_LOG_TRACE);
            breaknext = true;
        }
        OOM_TEST(NULL, _oom_test(NULL));
    } FCT_TEST_END()

    FCT_TEST_BGN(basic_client_nohost)
    {
        //jw_log_set_level(JW_LOG_TRACE);

        jw_client    *client;
        struct event_base *evbase;
        struct event      *failsafeEvent;
        jw_test_echosrv    echosrv;
        jw_htable    *config;
        jw_workq     *workq;

        fct_req(_test_init(&evbase, &failsafeEvent, &config, &workq, &echosrv));
        fct_req(jw_client_create(workq, &client, NULL));
        jw_htable_remove(config, JW_STREAM_CONFIG_HOST);

        _bindEvent(client, JW_CLIENT_EVENT_CONNECTED,         _onConnected,    NULL);
        _bindEvent(client, JW_CLIENT_EVENT_DISCONNECTED,      _onDisconnected, NULL);
        _bindEvent(client, JW_CLIENT_EVENT_DESTROYED,         _onDestroyed,    NULL);
        _bindEvent(client, JW_CLIENT_EVENT_PRESENCE_SENT,     _onStanzaSent,   NULL);
        _bindEvent(client, JW_CLIENT_EVENT_PRESENCE_RECEIVED, _onStanzaRecv,   NULL);

        fct_chk(jw_client_connect(client, config, NULL));

        // get things going
        _clientState = START;
        _fail        = false;
        event_base_dispatch(evbase);
        fct_req(!_test_get_timed_out());
        fct_chk(_clientState == DISCONNECTED);
        fct_chk(!_fail);

        jw_client_destroy(client);
        event_base_loop(evbase, EVLOOP_NONBLOCK);
        fct_chk(_clientState == DESTROYED);

        _test_cleanup(evbase, failsafeEvent, config, workq, echosrv);
    } FCT_TEST_END()

    FCT_TEST_BGN(basic_client_jidportonly)
    {
        //jw_log_set_level(JW_LOG_TRACE);

        jw_client    *client;
        struct event_base *evbase;
        struct event      *failsafeEvent;
        jw_test_echosrv    echosrv;
        jw_htable    *config;
        jw_workq     *workq;

        fct_req(_test_init(&evbase, &failsafeEvent, &config, &workq, &echosrv));
        fct_req(jw_client_create(workq, &client, NULL));

        jw_htable_remove(config, JW_STREAM_CONFIG_HOST);
        jw_htable_remove(config, JW_CLIENT_CONFIG_STREAM_TYPE);

        _bindEvent(client, JW_CLIENT_EVENT_CONNECTED,         _onConnected,    NULL);
        _bindEvent(client, JW_CLIENT_EVENT_DISCONNECTED,      _onDisconnected, NULL);
        _bindEvent(client, JW_CLIENT_EVENT_DESTROYED,         _onDestroyed,    NULL);
        _bindEvent(client, JW_CLIENT_EVENT_PRESENCE_SENT,     _onStanzaSent,   NULL);
        _bindEvent(client, JW_CLIENT_EVENT_PRESENCE_RECEIVED, _onStanzaRecv,   NULL);

        fct_chk(jw_client_connect(client, config, NULL));

        // get things going
        _clientState = START;
        _fail        = false;
        event_base_dispatch(evbase);
        fct_req(!_test_get_timed_out());
        fct_chk(_clientState == DISCONNECTED);
        fct_chk(!_fail);

        jw_client_destroy(client);
        event_base_loop(evbase, EVLOOP_NONBLOCK);
        fct_chk(_clientState == DESTROYED);

        _test_cleanup(evbase, failsafeEvent, config, workq, echosrv);
    } FCT_TEST_END()

    FCT_TEST_BGN(client_received_events)
    {
        //jw_log_set_level(JW_LOG_TRACE);

        jw_client    *client;
        struct event_base *evbase;
        struct event      *failsafeEvent;
        jw_test_echosrv    echosrv;
        jw_htable    *config;
        jw_workq     *workq;

        fct_req(_test_init(&evbase, &failsafeEvent, &config, &workq, &echosrv));
        fct_req(jw_client_create(workq, &client, NULL));

        _bindEvent(client, JW_CLIENT_EVENT_CONNECTED,         _onConnected,    NULL);
        _bindEvent(client, JW_CLIENT_EVENT_DISCONNECTED,      _onDisconnected, NULL);
        _bindEvent(client, JW_CLIENT_EVENT_DESTROYED,         _onDestroyed,    NULL);
        _bindEvent(client, JW_CLIENT_EVENT_PRESENCE_SENT,     _onStanzaSent,   NULL);
        _bindEvent(client, JW_CLIENT_EVENT_BEFORE_PRESENCE_RECEIVED,
                                                 _receivedHandledTestCallback, NULL);
        _bindEvent(client, JW_CLIENT_EVENT_PRESENCE_RECEIVED, _failIfCalled, NULL);

        fct_chk(jw_client_connect(client, config, NULL));

        // get things going
        _clientState = START;
        _fail        = false;
        event_base_dispatch(evbase);
        fct_req(!_test_get_timed_out());
        fct_chk(_clientState == DISCONNECTED);
        fct_chk(!_fail);

        jw_client_destroy(client);
        event_base_loop(evbase, EVLOOP_NONBLOCK);
        fct_chk(_clientState == DESTROYED);

        _test_cleanup(evbase, failsafeEvent, config, workq, echosrv);
    } FCT_TEST_END()

    FCT_TEST_BGN(client_connected_jid)
    {
        //jw_log_set_level(JW_LOG_TRACE);

        jw_client    *client;
        struct event_base *evbase;
        struct event      *failsafeEvent;
        jw_test_echosrv    echosrv;
        jw_htable    *config;
        jw_workq     *workq;

        fct_req(_test_init(&evbase, &failsafeEvent, &config, &workq, &echosrv));
        fct_req(jw_client_create(workq, &client, NULL));

        _bindEvent(client, JW_CLIENT_EVENT_STATUSCHANGED, _onStatusChanged,    NULL);
        _bindEvent(client, JW_CLIENT_EVENT_CONNECTED,         _onConnected,    NULL);
        _bindEvent(client, JW_CLIENT_EVENT_DISCONNECTED,      _onDisconnected, NULL);
        _bindEvent(client, JW_CLIENT_EVENT_DESTROYED,         _onDestroyed,    NULL);
        _bindEvent(client, JW_CLIENT_EVENT_PRESENCE_SENT,     _onStanzaSent,   NULL);
        _bindEvent(client, JW_CLIENT_EVENT_PRESENCE_RECEIVED, _onStanzaRecv,   NULL);

        fct_chk(jw_client_connect(client, config, NULL));
        _clientState = START;
        _fail        = false;
        event_base_dispatch(evbase);
        fct_req(!_test_get_timed_out());
        fct_chk(_clientState == DISCONNECTED);
        fct_chk(!_fail);

        jw_client_destroy(client);
        event_base_loop(evbase, EVLOOP_NONBLOCK);
        fct_chk(_clientState == DESTROYED);

        _test_cleanup(evbase, failsafeEvent, config, workq, echosrv);
    } FCT_TEST_END()

    FCT_TEST_BGN(client_explicit_resource_binding)
    {
        //jw_log_set_level(JW_LOG_TRACE);

        jw_client    *client;
        struct event_base *evbase;
        struct event      *failsafeEvent;
        jw_test_echosrv    echosrv;
        jw_htable    *config;
        jw_workq     *workq;

        fct_req(_test_init(&evbase, &failsafeEvent, &config, &workq, &echosrv));
        fct_req(jw_client_create(workq, &client, NULL));

        // test that bare jid binds server supplied resource
        jw_test_echosrv_core echosrv_core =
                _jw_test_echosrv_get_echosrv_core(echosrv);
        _jw_test_echosrv_core_set_bind_jid(echosrv_core, ECHOSRV_JID_FULL);

        _bindEvent(client, JW_CLIENT_EVENT_CONNECTED,         _onConnected,    NULL);
        _bindEvent(client, JW_CLIENT_EVENT_DISCONNECTED,      _onDisconnected, NULL);
        _bindEvent(client, JW_CLIENT_EVENT_DESTROYED,         _onDestroyed,    NULL);
        _bindEvent(client, JW_CLIENT_EVENT_PRESENCE_SENT,     _onStanzaSent,   NULL);
        _bindEvent(client, JW_CLIENT_EVENT_PRESENCE_RECEIVED, _onStanzaRecv,   NULL);

        fct_chk(jw_client_connect(client, config, NULL));
        _clientState = START;
        _fail        = false;
        event_base_dispatch(evbase);
        fct_req(!_test_get_timed_out());
        fct_chk(_clientState == DISCONNECTED);
        fct_chk(!_fail);

        // test that resource was specified by server
        fct_chk_eq_str(jw_htable_get(config, CLIENT_TEST_JID),
                       ECHOSRV_JID_FULL);
        jw_client_destroy(client);
        event_base_loop(evbase, EVLOOP_NONBLOCK);
        fct_chk(_clientState == DESTROYED);

        _test_cleanup(evbase, failsafeEvent, config, workq, echosrv);

        // test full jid binds client's resource
        fct_req(_test_init(&evbase, &failsafeEvent, &config, &workq, &echosrv));
        fct_req(jw_client_create(workq, &client, NULL));

        echosrv_core = _jw_test_echosrv_get_echosrv_core(echosrv);
        _jw_test_echosrv_core_set_bind_jid(echosrv_core, ECHOSRV_JID_FULL);
        jw_htable_put(config,
                      JW_CLIENT_CONFIG_USERJID,
                      (void *)CLIENT_JID_FULL,
                      NULL, NULL);

        _bindEvent(client, JW_CLIENT_EVENT_CONNECTED,         _onConnected,    NULL);
        _bindEvent(client, JW_CLIENT_EVENT_DISCONNECTED,      _onDisconnected, NULL);
        _bindEvent(client, JW_CLIENT_EVENT_DESTROYED,         _onDestroyed,    NULL);
        _bindEvent(client, JW_CLIENT_EVENT_PRESENCE_SENT,     _onStanzaSent,   NULL);
        _bindEvent(client, JW_CLIENT_EVENT_PRESENCE_RECEIVED, _onStanzaRecv,   NULL);

        fct_chk(jw_client_connect(client, config, NULL));
        _clientState = START;
        _fail        = false;
        event_base_dispatch(evbase);
        fct_req(!_test_get_timed_out());
        fct_chk(_clientState == DISCONNECTED);
        fct_chk(!_fail);

        // test that resource was specified by client
        fct_chk_eq_str(jw_htable_get(config, CLIENT_TEST_JID),
                       ECHOSRV_JID_CLIENT_RESOURCE);
        jw_client_destroy(client);
        event_base_loop(evbase, EVLOOP_NONBLOCK);
        fct_chk(_clientState == DESTROYED);

        _test_cleanup(evbase, failsafeEvent, config, workq, echosrv);
    } FCT_TEST_END()

    FCT_TEST_BGN(client_sm)
    {
        //jw_log_set_level(JW_LOG_TRACE);

        jw_client    *client;
        struct event_base *evbase;
        struct event      *failsafeEvent;
        jw_test_echosrv    echosrv;
        jw_htable    *config;
        jw_workq     *workq;

        fct_req(_test_init(&evbase, &failsafeEvent, &config, &workq, &echosrv));
        fct_req(jw_client_create(workq, &client, NULL));

        // enable stream management in echosrv
        jw_test_echosrv_core echosrv_core =
                _jw_test_echosrv_get_echosrv_core(echosrv);
        fct_req(_jw_test_echosrv_core_feature_ctrl(echosrv_core,
                         JW_ECHOSRV_FEATURE_SM, JW_ECHOSRV_FEATURE_NONE, NULL));

        // cause ack requests to be sent after every other stanza
        static const uint32_t SM_ACK_THRESH = 2;
        fct_req(jw_htable_put(config, JW_CLIENT_CONFIG_SM_ACK_REQUEST_THRESHOLD,
                              (void *)(uintptr_t)SM_ACK_THRESH, NULL, NULL));

        static const uint32_t SM_COUNTDOWN = 10;
        uint32_t countdown = SM_COUNTDOWN;
        _bindEvent(client, JW_CLIENT_EVENT_CONNECTED,         _onConnected,    NULL);
        _bindEvent(client, JW_CLIENT_EVENT_DISCONNECTED,      _onDisconnected, NULL);
        _bindEvent(client, JW_CLIENT_EVENT_DESTROYED,         _onDestroyed,    NULL);
        _bindEvent(client, JW_CLIENT_EVENT_PRESENCE_SENT,     _onStanzaSent,   NULL);
        _bindEvent(client, JW_CLIENT_EVENT_PRESENCE_RECEIVED, _onStanzaRecv,   &countdown);
        _bindEvent(client, JW_CLIENT_EVENT_MESSAGE_RECEIVED,  _onStanzaRecv,   &countdown);

        fct_chk(jw_client_connect(client, config, NULL));

        // get things going
        _clientState = START;
        _fail        = false;
        event_base_dispatch(evbase);
        fct_req(!_test_get_timed_out());
        fct_chk(_clientState == DISCONNECTED);
        fct_chk(!_fail);

        // check state management stats
        _stream_mgmt_state sms = _jw_client_get_stream_mgmt_state(client);

        fct_chk_eq_int(SM_ACK_THRESH, sms->ack_request_threshold);
        fct_chk_eq_int(SM_SUPPORTED|SM_ENABLED, sms->flags);
        // +1 for presence stanza that jw_client sends on connection
        fct_chk_eq_int(SM_COUNTDOWN+1, sms->num_received_stanzas);
        fct_chk_eq_int(sms->num_server_acked_stanzas + sms->num_unacked_stanzas,
                       sms->num_received_stanzas);

        jw_client_destroy(client);
        event_base_loop(evbase, EVLOOP_NONBLOCK);
        fct_chk(_clientState == DESTROYED);

        _test_cleanup(evbase, failsafeEvent, config, workq, echosrv);
    } FCT_TEST_END()

    FCT_TEST_BGN(client_reconnect_api)
    {
        //jw_log_set_level(JW_LOG_TRACE);

        struct event_base               *evbase;
        jw_htable                  *config;
        jw_client                  *client;
        jw_dom_ctx                 *ctx;
        jw_client_reconnect_status *reconn;
        jw_workq                   *workq;

        //test reconnect helper funcs
        //double time value conversion to milliseconds
        uint32_t count = _jw_client_reconn_next_countdown(500, 1);
        fct_chk(count >= 250 && count <= 750);
        count = _jw_client_reconn_next_countdown(580, 1);
        fct_chk(count >= 290 && count <= 870);
        count = _jw_client_reconn_next_countdown(588, 1);
        fct_chk(count >= 294 && count <= 882);
        count = _jw_client_reconn_next_countdown(3500, 1);
        fct_chk(count >= 1750 && count <= 5250);
        count = _jw_client_reconn_next_countdown(3580, 1);
        fct_chk(count >= 1790 && count <= 5370);
        count = _jw_client_reconn_next_countdown(3588, 1);
        fct_chk(count >= 1794 && count <= 5382);
        //next countdown testing
        count = _jw_client_reconn_next_countdown(6000, 1);
        fct_chk(count >= 3000 && count <= 9000);
        count = _jw_client_reconn_next_countdown(6000, 1);
        fct_chk(count >= 3000 && count <= 9000);
        count = _jw_client_reconn_next_countdown(60000, 1);
        fct_chk(count >= 30000 && count <= 90000);
        count = _jw_client_reconn_next_countdown(11000, 1);
        fct_chk(count >= 5500 && count <= 16500);
        count = _jw_client_reconn_next_countdown(1000, 1);
        fct_chk(count >= 500 && count <= 1500);
        count = _jw_client_reconn_next_countdown(2000, 1);
        fct_chk(count >= 1000 && count <= 3000);
        //dbl until max is reached
        count = _jw_client_reconn_next_countdown(3000, 1);
        fct_chk(count >= 1500 && count <= 4500);
        count = _jw_client_reconn_next_countdown(3000, 2);
        fct_chk(count >= 4500 && count <= 7500);
        count = _jw_client_reconn_next_countdown(3000, 3);
        fct_chk(count >= 10500 && count <= 13500);
        count = _jw_client_reconn_next_countdown(3000, 4);
        fct_chk(count >= 22500 && count <= 25500);
        count = _jw_client_reconn_next_countdown(3000, 5);
        fct_chk(count >= 46500 && count <= 49500);
        count = _jw_client_reconn_next_countdown(3000, 6);
        fct_chk(count >= 94500 && count <= 97500);
        count = _jw_client_reconn_next_countdown(3000, 7);
        fct_chk(count >= 190500 && count <= 193500);
        count = _jw_client_reconn_next_countdown(3000, 8);
        fct_chk(count >= 382500 && count <= 385500);
        count = _jw_client_reconn_next_countdown(3000, 9);
        fct_chk(count >= 598500 && count <= 601500);
        count = _jw_client_reconn_next_countdown(3000, 10);
        fct_chk(count >= 598500 && count <= 601500);
        //check max
        count = _jw_client_reconn_next_countdown(50000, 6);
        fct_chk(count >= 575000 && count <= 625000);
        count = _jw_client_reconn_next_countdown(50000, 7);
        fct_chk(count >= 575000 && count <= 625000);
        //check attempt upper bound
        count = _jw_client_reconn_next_countdown(2000, 31);
        fct_chk(count >= 599000 && count <= 601000);
        count = _jw_client_reconn_next_countdown(2000, 32);
        fct_chk(count >= 599000 && count <= 601000);
        count = _jw_client_reconn_next_countdown(2000, 33);
        fct_chk(count >= 599000 && count <= 601000);
        count = _jw_client_reconn_next_countdown(2000, UINT32_MAX);
        fct_chk(count >= 599000 && count <= 601000);
        //base upperbound
        count = _jw_client_reconn_next_countdown(UINT32_MAX, UINT32_MAX);
        fct_chk(count == 600000);
        //attempt, base lower bound
        count = _jw_client_reconn_next_countdown(2000, 0);
        fct_chk(count == 0);
        count = _jw_client_reconn_next_countdown(0, 2);
        fct_chk(count == 0);

        fct_req(_test_init(&evbase, NULL, &config, &workq, NULL));
        fct_req(jw_client_create(workq, &client, NULL));

        jw_dom_context_create(&ctx, NULL);
        fct_chk(!_jw_client_reconn_is_disconnect_error(_new_stream_error(ctx, JW_STREAM_ERROR_NO_RSRC)));
        fct_chk(!_jw_client_reconn_is_disconnect_error(_new_stream_error(ctx, JW_STREAM_ERROR_SYSTEM_SHUTDOWN)));
        fct_chk(!_jw_client_reconn_is_disconnect_error(_new_stream_error(ctx, JW_STREAM_ERROR_SEE_OTHER_HOST)));
        fct_chk(!_jw_client_reconn_is_disconnect_error(_new_stream_error(ctx, JW_STREAM_ERROR_CONFLICT)));

        fct_chk(_jw_client_reconn_is_disconnect_error(_new_stream_error(ctx, JW_STREAM_ERROR_CONN_TIMEOUT)));
        fct_chk(_jw_client_reconn_is_disconnect_error(_new_stream_error(ctx, JW_STREAM_ERROR_REMOTE_CONN_FAILED)));
        fct_chk(_jw_client_reconn_is_disconnect_error(_new_stream_error(ctx, JW_STREAM_ERROR_RESET)));
        fct_chk(_jw_client_reconn_is_disconnect_error(_new_stream_error(ctx, JW_STREAM_ERROR_POLICY_VIOLATION)));
        jw_dom_context_destroy(ctx);

        fct_chk(!jw_client_is_reconnect_pending(client));
        reconn = _jw_client_reconnect_state(client);
        fct_chk_eq_int(0, jw_client_reconnect_get_countdown(reconn));
        fct_chk_eq_int(0, jw_client_reconnect_get_attempts(reconn));
        fct_chk(JW_CLIENT_RECONNECT_CANCELED == jw_client_reconnect_get_status(reconn));

        jw_client_destroy(client);
        event_base_loop(evbase, EVLOOP_NONBLOCK);
        _test_cleanup(evbase, NULL, config, workq, NULL);
    } FCT_TEST_END()

    FCT_TEST_BGN(client_reconnect)
    {
        //jw_log_set_level(JW_LOG_TRACE);

        jw_client    *client;
        testDataType      *data;
        //jw_err             err;

        data = _newTestData();
        fct_req(NULL != data);

        fct_req(jw_client_create(data->workq, &client, NULL));
        //this error should normally generate a reconnect
        data->error = _new_stream_error(NULL, JW_STREAM_ERROR_REMOTE_CONN_FAILED);
        jw_dom_context_destroy(jw_dom_get_context(data->error));
        data->error = NULL;
        fct_req(_bindConnectEvents(client, &RECONNECT_CALLBACKS, data));
        _bindEvent(client, JW_CLIENT_EVENT_MESSAGE_RECEIVED, _reconOnStanzaRecv, data);

        //Make sure reconnect is not attempted when disabled
        fct_req(jw_htable_put(data->config,
                              JW_CLIENT_CONFIG_RECONNECT_BASE_COUNTDOWN,
                              "0", NULL, NULL));

        data->counter = 5; //exchange 5 messages and disconnect
        data->state = START;
        data->failed = false;

        fct_chk(jw_client_connect(client, data->config, NULL));
        event_base_dispatch(data->evbase);

        fct_req(!_test_get_timed_out());
        fct_chk(!jw_client_is_reconnect_pending(client));
        fct_chk(data->state == DISCONNECTED);
        /*
        jw_echosrv_destroy(data->echosrv);
        jw_echosrv_create(data->evbase, &data->echosrv, NULL);


        //_finalizeTestData(data);
        //data = _newTestData();
        //fct_req(NULL != data);
        if (data->error)
        {
            jw_dom_context_destroy(jw_dom_get_context(data->error));
        }
        data->error = _new_stream_error(NULL, JW_STREAM_ERROR_REMOTE_CONN_FAILED);

        //test user called disconnect does not start reconnect
        fct_req(jw_htable_put(data->config, JW_CLIENT_CONFIG_RECONNECT_BASE_COUNTDOWN, "0.25", NULL, NULL));
        data->counter = 0;
        data->state = START;
        data->failed = false;

        fct_chk(jw_client_connect(client, data->config, NULL));
        event_base_dispatch(data->evbase);

        //fct_req(!_test_get_timed_out());
        fct_chk(!jw_client_is_reconnect_pending(client));
        fct_chk(data->state == DISCONNECTED);

        if (data->error)
        {
            jw_dom_context_destroy(jw_dom_get_context(data->error));
        }
        data->error = _new_stream_error(NULL, JW_STREAM_ERROR_REMOTE_CONN_FAILED);
        //_finalizeTestData(data);
        //data = _newTestData();
        jw_echosrv_destroy(data->echosrv);
        jw_echosrv_create(data->evbase, &data->echosrv, NULL);
        data->counter = 0;
        data->state = START;
        data->failed = false;

        fct_chk(jw_client_connect(client, data->config, NULL));
        event_base_dispatch(data->evbase);

        //fct_req(!_test_get_timed_out());
        fct_chk(!jw_client_is_reconnect_pending(client));
        */
        //these tests should NOT result in a reconnection attempt
        //JW_STREAM_ERROR_NO_RSRC, JW_STREAM_ERROR_SYSTEM_SHUTDOWN, JW_STREAM_ERROR_SEE_OTHER_HOST

        //these tests should cause a reconnect to be scheduled
        //JW_STREAM_ERROR_CONN_TIMEOUT, JW_STREAM_ERROR_REMOTE_CONN_FAILED, JW_STREAM_ERROR_RESET

        //establish a connection, schedule a reconnect attempt by disconnecting with
        //an acceptable error and then test error handling within reconnection
        //by setting echosrv response stanza to return error at first client ping

        //these tests should stop any reconnection attempts
        //JW_STREAM_ERROR_SYSTEM_SHUTDOWN, JW_STREAM_ERROR_CONFLICT

        //these tests should cause only this reconnection attempt to fail
        //JW_STREAM_ERROR_SEE_OTHER_HOST, JW_STREAM_ERROR_POLICY_VIOLATION, JW_STREAM_ERROR_CONN_TIMEOUT

        //loop to allow cient destruction events

        _unbindConnectEvents(client, &RECONNECT_CALLBACKS);
        _unbindEvent(client, JW_CLIENT_EVENT_MESSAGE_RECEIVED, _reconOnStanzaRecv);

        jw_client_destroy(client);
        event_base_loop(data->evbase, EVLOOP_NONBLOCK);

        _finalizeTestData(data);
    } FCT_TEST_END()
} FCTMF_FIXTURE_SUITE_END()
