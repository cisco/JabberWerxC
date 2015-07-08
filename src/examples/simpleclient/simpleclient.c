    /**
 * \file
 * JabberWerxC Simple Client
 *
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2011 Cisco Systems, Inc.  All Rights Reserved.
 */

/**
 * Note: This program is only a demo and does not recover gracefully from many
 * types of failure.
 */

#include "simpleclient_utils.h"
#include "option_parser.h"

#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <arpa/inet.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>

#include <jabberwerx/jabberwerx.h>
#include <jabberwerx/client.h>
#include <jabberwerx/crypto/tls.h>
#include <jabberwerx/util/log.h>

#include <event2/event.h>

#define DISCO_ITEMS "{http://jabber.org/protocol/disco#items}"
#define DISCO_INFO "{http://jabber.org/protocol/disco#info}"

// SIGINT event object
struct event *g_sigintEvent = NULL;

static jw_dom_node *get_next_element(jw_dom_node *node, const char* ename)
{
    jw_dom_node *sib = jw_dom_get_sibling(node);
    while (sib)
    {
        if (jw_dom_get_nodetype(sib) == JW_DOM_TYPE_ELEMENT)
        {
            if (jw_strcmp(jw_dom_get_ename(sib), ename) == 0)
            {
                return sib;
            }
        }
        sib = jw_dom_get_sibling(sib);
    }
    return NULL;
}

static void discoInfoCb(jw_dom_node *result, void *user_data)
{
    UNUSED_PARAM(user_data);

    dumpEventData(result, "Got disco#info result");

    if (!result)
    {
        // timeout
        jw_log(JW_LOG_WARN, "Timeout in disco#info");
        return;
    }

    const char *from = jw_dom_get_attribute(result, "{}from");
    const char *typ = jw_dom_get_attribute(result, "{}type");
    printf("ITEM: '%s': %s\n", from, typ);

    if (jw_strcmp(typ, "result"))
    {
        jw_log(JW_LOG_WARN, "Error in disco#info");
        return;
    }

    jw_dom_node *query = jw_dom_get_first_element(result, DISCO_INFO "query");
    if (!query)
    {
        jw_log(JW_LOG_WARN, "Invalid protocol in disco#info");
        return;
    }

    // identities
    jw_dom_node *ident = jw_dom_get_first_element(query, DISCO_INFO "identity");
    while (ident)
    {
        printf("  IDENTITY (%s/%s): %s\n",
            jw_dom_get_attribute(ident, "{}category"),
            jw_dom_get_attribute(ident, "{}type"),
            jw_dom_get_attribute(ident, "{}name"));
        ident = get_next_element(ident, DISCO_INFO "identity");
    }

    // features
    jw_dom_node *feat = jw_dom_get_first_element(query, DISCO_INFO "feature");
    while (feat)
    {
        printf("  FEATURE: %s\n",
            jw_dom_get_attribute(feat, "{}var"));
        feat = get_next_element(feat, DISCO_INFO "feat");
    }
}

static void discoItemsCb(jw_dom_node *result, void *user_data)
{
    jw_client *client = user_data;

    dumpEventData(result, "Got disco#items result");

    // can either be NULL(timeout), result, or error.
    if (!result)
    {
        jw_log(JW_LOG_WARN, "Timeout in disco#items");
        return;
    }
    if (jw_strcmp(jw_dom_get_attribute(result, "{}type"), "result"))
    {
        jw_log(JW_LOG_WARN, "Error in disco#items");
        return;
    }
    jw_dom_node *query = jw_dom_get_first_element(result, DISCO_ITEMS "query");
    if (!query)
    {
        jw_log(JW_LOG_WARN, "Invalid protocol in disco#items");
        return;
    }
    jw_dom_node *item = jw_dom_get_first_element(query, DISCO_ITEMS "item");
    while (item)
    {
        const char *jid = jw_dom_get_attribute(item, "jid");
        if (jid)
        {
            jw_dom_ctx *ctx;
            jw_dom_node *iq;
            jw_dom_node *info_query;
            jw_err err;

            if (!jw_dom_context_create(&ctx, &err))
            {
                jw_log_err(JW_LOG_ERROR, &err, "Error creating DOM context");
                return;
            }
            if (!jw_dom_element_create(ctx, "{jabber:client}iq", &iq, &err) ||
                !jw_dom_set_attribute(iq, "{}to", jid, &err) ||
                !jw_dom_set_attribute(iq, "{}type", "get", &err) ||
                !jw_dom_element_create(ctx,
                                       DISCO_INFO "query",
                                       &info_query,
                                       &err) ||
                !jw_dom_add_child(iq, info_query, &err))
            {
                jw_log_err(JW_LOG_ERROR, &err, "Error creating IQ");
                jw_dom_context_destroy(ctx);
                return;
            }

            if (!jw_client_track_iq(client, iq, discoInfoCb, client, 30, &err))
            {
                jw_log_err(JW_LOG_ERROR, &err, "Error sending disco IQ");
                return;
            }
        }

        item = get_next_element(item, DISCO_ITEMS "item");
    }
}

static void clientConnectedCb(jw_event_data event, void *arg)
{
    UNUSED_PARAM(arg);

    jw_client *client = event->source;
    jw_jid *jid = jw_client_get_jid(client);
    jw_dom_ctx *ctx;
    jw_dom_node *iq;
    jw_dom_node *query;
    jw_err err;

    printf("client connected as: '%s'\n", jw_jid_get_full(jid));

    if (!jw_dom_context_create(&ctx, &err))
    {
        jw_log_err(JW_LOG_ERROR, &err, "Error creating DOM context");
        return;
    }
    if (!jw_dom_element_create(ctx, "{jabber:client}iq", &iq, &err) ||
        !jw_dom_set_attribute(iq, "{}to", jw_jid_get_domain(jid), &err) ||
        !jw_dom_set_attribute(iq, "{}type", "get", &err) ||
        !jw_dom_element_create(ctx,
                               DISCO_ITEMS "query",
                               &query,
                               &err) ||
        !jw_dom_add_child(iq, query, &err))
    {
        jw_log_err(JW_LOG_ERROR, &err, "Error creating IQ");
        jw_dom_context_destroy(ctx);
        return;
    }

    if (!jw_client_track_iq(client, iq, discoItemsCb, client, 30, &err))
    {
        jw_log_err(JW_LOG_ERROR, &err, "Error sending disco IQ");
        return;
    }
}

static void clientDisconnectedCb(jw_event_data event, void *arg)
{
    UNUSED_PARAM(arg);

    jw_client *client = event->source;

    dumpEventData(event->data, "client disconnected");

    if (jw_client_is_reconnect_pending(client))
    {
        printf("Waiting for reconnect\n");
    }
    else
    {
        jw_client_destroy(client);
    }
}

static void clientDestroyedCb(jw_event_data event, void *arg)
{
    UNUSED_PARAM(arg);

    dumpEventData(event->data, "client destroyed");

    // signal is set after successful connection
    if (g_sigintEvent)
    {
        event_del(g_sigintEvent);
    }
}

static void clientStatusChangedCb(jw_event_data event, void *arg)
{
    UNUSED_PARAM(arg);

    jw_client_status *status = event->data;

    jw_client *client = event->source;
    jw_jid *jid = jw_client_get_jid(client);

    jw_client_statustype prev = jw_client_status_get_previous(status);
    jw_client_statustype cur = jw_client_status_get_next(status);

    printf("client status changed: %s -> %s (jid: %s)\n",
           getStatusString(prev), getStatusString(cur),
           jid ? jw_jid_get_full(jid) : "unavailable");

    dumpEventData(jw_client_status_get_error(status), NULL);
}

static void clientResumedCb(jw_event_data event, void *arg)
{
    UNUSED_PARAM(arg);
    dumpEventData(event->data, "session RESUMED");
}
static void clientPausedCb(jw_event_data event, void *arg)
{
    UNUSED_PARAM(arg);
    dumpEventData(event->data, "session PAUSED");
}

static void clientReconnectStatusChangedCb(jw_event_data event, void *arg)
{
    UNUSED_PARAM(arg);

    jw_client_reconnect_status *status = event->data;
    jw_client_reconnect_statustype st = jw_client_reconnect_get_status(status);

    switch (st)
    {
        case JW_CLIENT_RECONNECT_CANCELED:
            printf("Reconnect attempt canceled\n");
            break;
        case JW_CLIENT_RECONNECT_PENDING:
            printf("Reconnect attempt #%u in %u seconds\n",
                   jw_client_reconnect_get_attempts(status),
                   jw_client_reconnect_get_countdown(status));
            break;
        case JW_CLIENT_RECONNECT_STARTING:
            printf("Starting reconnect attempt #%u\n",
                   jw_client_reconnect_get_attempts(status));
            break;
        default:
            printf("Unknown reconnect status\n");
    }
}

static void clientBeforePresenceReceivedCb(jw_event_data event, void *arg)
{
    UNUSED_PARAM(arg);
    dumpEventData(event->data, "before presence received");
}

static void clientPresenceReceivedCb(jw_event_data event, void *arg)
{
    UNUSED_PARAM(arg);
    dumpEventData(event->data, "presence received");
}

static void clientAfterPresenceReceivedCb(jw_event_data event, void *arg)
{
    UNUSED_PARAM(arg);
    dumpEventData(event->data, "after presence received");
}

static void clientBeforeMessageReceivedCb(jw_event_data event, void *arg)
{
    UNUSED_PARAM(arg);
    dumpEventData(event->data, "before message received");
}

static void clientMessageReceivedCb(jw_event_data event, void *arg)
{
    UNUSED_PARAM(arg);
    dumpEventData(event->data, "message received");
}

static void clientAfterMessageReceivedCb(jw_event_data event, void *arg)
{
    UNUSED_PARAM(arg);

    jw_dom_node *node = event->data;
    jw_client *client = event->source;

    dumpEventData(node, "after message received");

    // if we're type chat let's spit this back to the sending client as
    // an example and exercise of client and stream protocol sends
    const char *type = jw_dom_get_attribute(node, "type");
    if (type && 0 == strcmp(type, "chat"))
    {
        jw_dom_context_retain(jw_dom_get_context(node), NULL);
        const char *to = jw_dom_get_attribute(node, "to");
        const char *from = jw_dom_get_attribute(node, "from");

        jw_dom_set_attribute(node, "{}from", to, NULL);
        jw_dom_set_attribute(node, "{}to", from, NULL);

        jw_client_send_stanza(client, node, NULL);
    }
}

static void clientBeforeIqReceivedCb(jw_event_data event, void *arg)
{
    UNUSED_PARAM(arg);
    dumpEventData(event->data, "before iq received");
}

static void clientIqReceivedCb(jw_event_data event, void *arg)
{
    UNUSED_PARAM(arg);
    dumpEventData(event->data, "iq received");
}

static void clientAfterIqReceivedCb(jw_event_data event, void *arg)
{
    UNUSED_PARAM(arg);
    dumpEventData(event->data, "after iq received");
}

static void clientBeforePresenceSentCb(jw_event_data event, void *arg)
{
    UNUSED_PARAM(arg);
    dumpEventData(event->data, "before presence sent");
}

static void clientPresenceSentCb(jw_event_data event, void *arg)
{
    UNUSED_PARAM(arg);
    dumpEventData(event->data, "presence sent");
}

static void clientBeforeMessageSentCb(jw_event_data event, void *arg)
{
    UNUSED_PARAM(arg);
    dumpEventData(event->data, "before message sent");
}

static void clientMessageSentCb(jw_event_data event, void *arg)
{
    UNUSED_PARAM(arg);
    dumpEventData(event->data, "message sent");
}

static void clientBeforeIqSentCb(jw_event_data event, void *arg)
{
    UNUSED_PARAM(arg);
    dumpEventData(event->data, "before iq sent");
}

static void clientIqSentCb(jw_event_data event, void *arg)
{
    UNUSED_PARAM(arg);
    dumpEventData(event->data, "iq sent");
}

/**
 * Callback triggered when an invalid certificate is found during the TLS
 * handshake. This example just auto accepts all certificates.
 * Actual implementations would use the given context to discover
 * what kind of error occurred and react accordingly by proceeding with, or
 * failing of, the connection attempt.
 *
 * NOTE: jw_tls_proceed MUST be called to complete the connection attempt.
 * NOTE: this is a work in progress. Certificate access is not currently
 *       implemented (but will be in the future).
 */
static void clientTlsAcceptCertCb(jw_tls_session *sess, void *arg)
{
    jw_log(JW_LOG_DEBUG,
           "clientTlsAcceptCertCb argument %s",
           (char*)arg);
    jw_tls_proceed(sess, true);
}

/**
 * Triggered when SIGINT (Ctrl-C) is detected
 */
static void sigintCb(evutil_socket_t fd, short events, void *arg)
{
    UNUSED_PARAM(fd);
    UNUSED_PARAM(events);

    jw_log(JW_LOG_INFO, "ctrl-c detected; disconnecting");

    jw_client *client = arg;

    jw_client_disconnect(client, JW_ERR_NONE);
}

/**
 * Sample for jw_client
 */
int main(int argc, char **argv)
{
    jw_err             err;
    jw_htable    *config    = NULL;
    jw_client    *client    = NULL;
    struct event_base *eventBase = NULL;

    jw_tls_accept_cb_htable_value acbv = { .cb = clientTlsAcceptCertCb };
    char *accept_arg = "accept";

    // parameters to retrieve from the commandline
    char *jid        = NULL;
    char *password   = NULL;
    char *streamType = NULL;
    char *hostname   = NULL;
    char *port       = NULL;
    char *uri        = NULL;
    int   verbosity  = JW_LOG_WARN;

    // set initial logging level
    jw_log_set_level(verbosity);

    if (!parseCommandline(argc, argv,
                          &jid, &password, &streamType, &hostname,
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

    if (!jw_htable_put(config, JW_TLS_CONFIG_ACCEPT_CB,  &acbv,    NULL, &err)
     || !jw_htable_put(config, JW_TLS_CONFIG_ACCEPT_CB_ARG,
                       accept_arg, NULL, &err)
     || !jw_htable_put(config, JW_CLIENT_CONFIG_USERJID, jid,      NULL, &err)
     || !jw_htable_put(config, JW_CLIENT_CONFIG_USERPW,  password, NULL, &err)
     || !jw_htable_put(config, JW_CLIENT_CONFIG_STREAM_TYPE,
                                                       streamType, NULL, &err)
     || (hostname &&
         !jw_htable_put(config, JW_STREAM_CONFIG_HOST, hostname,   NULL, &err))
     || (port &&
         !jw_htable_put(config, JW_STREAM_CONFIG_PORT, port,       NULL, &err))
     || (uri &&
         !jw_htable_put(config, JW_STREAM_CONFIG_URI,  uri,        NULL, &err)))
    {
        jw_log_err(JW_LOG_ERROR, &err, "error populating configuration htable");
        return 1;
    }

    printf("This is the Jabberwerx client demo.\n\n");

    if (!jw_client_create(workq, &client, &err))
    {
        jw_log_err(JW_LOG_ERROR, &err, "could not create client");
        return 1;
    }

#define EVT_BIND(ename, cb, arg) \
    jw_event_bind(jw_client_event(client, (ename)), (cb), (arg), &err)

    // bind callbacks to all advertised events
    EVT_BIND(JW_CLIENT_EVENT_CONNECTED,     clientConnectedCb,     NULL);
    EVT_BIND(JW_CLIENT_EVENT_DISCONNECTED,  clientDisconnectedCb,  NULL);
    EVT_BIND(JW_CLIENT_EVENT_DESTROYED,     clientDestroyedCb,     NULL);
    EVT_BIND(JW_CLIENT_EVENT_STATUSCHANGED, clientStatusChangedCb, NULL);
    EVT_BIND(JW_CLIENT_EVENT_RECONNECT_STATUSCHANGED, clientReconnectStatusChangedCb, NULL);
    EVT_BIND(JW_CLIENT_EVENT_SESSION_RESUMED,clientResumedCb,     NULL);
    EVT_BIND(JW_CLIENT_EVENT_SESSION_PAUSED, clientPausedCb,  NULL);

    EVT_BIND(JW_CLIENT_EVENT_BEFORE_PRESENCE_RECEIVED, clientBeforePresenceReceivedCb, NULL);
    EVT_BIND(JW_CLIENT_EVENT_PRESENCE_RECEIVED,        clientPresenceReceivedCb,       NULL);
    EVT_BIND(JW_CLIENT_EVENT_AFTER_PRESENCE_RECEIVED,  clientAfterPresenceReceivedCb,  NULL);
    EVT_BIND(JW_CLIENT_EVENT_BEFORE_PRESENCE_SENT,     clientBeforePresenceSentCb,     NULL);
    EVT_BIND(JW_CLIENT_EVENT_PRESENCE_SENT,            clientPresenceSentCb,           NULL);

    EVT_BIND(JW_CLIENT_EVENT_BEFORE_MESSAGE_RECEIVED, clientBeforeMessageReceivedCb, NULL);
    EVT_BIND(JW_CLIENT_EVENT_MESSAGE_RECEIVED,        clientMessageReceivedCb,       NULL);
    EVT_BIND(JW_CLIENT_EVENT_AFTER_MESSAGE_RECEIVED,  clientAfterMessageReceivedCb,  NULL);
    EVT_BIND(JW_CLIENT_EVENT_BEFORE_MESSAGE_SENT,     clientBeforeMessageSentCb,     NULL);
    EVT_BIND(JW_CLIENT_EVENT_MESSAGE_SENT,            clientMessageSentCb,           NULL);

    EVT_BIND(JW_CLIENT_EVENT_BEFORE_IQ_RECEIVED, clientBeforeIqReceivedCb, NULL);
    EVT_BIND(JW_CLIENT_EVENT_IQ_RECEIVED,        clientIqReceivedCb,       NULL);
    EVT_BIND(JW_CLIENT_EVENT_AFTER_IQ_RECEIVED,  clientAfterIqReceivedCb,  NULL);
    EVT_BIND(JW_CLIENT_EVENT_BEFORE_IQ_SENT,     clientBeforeIqSentCb,     NULL);
    EVT_BIND(JW_CLIENT_EVENT_IQ_SENT,            clientIqSentCb,           NULL);
#undef EVT_BIND

    if (!jw_client_connect(client, config, &err))
    {
        jw_log_err(JW_LOG_ERROR, &err, "could not connect to specified server");
        jw_client_destroy(client);
        return 1;
    }

    g_sigintEvent = event_new(eventBase, SIGINT, EV_SIGNAL, sigintCb, client);
    if (NULL == g_sigintEvent || 0 != event_add(g_sigintEvent, NULL))
    {
        jw_log(JW_LOG_ERROR, "could not register signal handler");
        return 1;
    }

    event_base_dispatch(eventBase);
    event_base_free(eventBase);

    jw_htable_destroy(config);
    jw_workq_destroy(workq);

    printf("Have a great day!\n");
    return 0;
}
