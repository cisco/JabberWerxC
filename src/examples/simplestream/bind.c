/**
 * \file
 * bind.c
 *
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2011 Cisco Systems, Inc.  All Rights Reserved.
 */

#include "bind.h"
#include "simplestream_defines.h"
#include "simplestream_utils.h"

#include <jabberwerx/util/log.h>
#include <jabberwerx/util/str.h>

#include <stdio.h>

static jw_dom_node *createBind()
{
    jw_dom_ctx *domCtx;
    jw_dom_node *iqDom;
    jw_dom_node *bindDom;

    jw_dom_context_create(&domCtx, NULL);

    jw_dom_element_create(domCtx, XMPP_CLIENT_IQ, &iqDom, NULL);
    jw_dom_set_attribute(iqDom, "{}id", "random_number", NULL);
    jw_dom_set_attribute(iqDom, "{}type", "set", NULL);


    jw_dom_element_create(domCtx, XMPP_BIND, &bindDom, NULL);
    jw_dom_add_child(iqDom, bindDom, NULL);

    return iqDom;
}

static bool findBind(jw_dom_node *streamNode)
{
    return (bool)(jw_dom_get_first_element(streamNode, XMPP_BIND) != NULL);
}

static const char *findJidFromBind(jw_dom_node *iq)
{
    jw_dom_node *bindNode = jw_dom_get_first_element(iq, XMPP_BIND);
    if (bindNode)
    {
        jw_dom_node *jid = jw_dom_get_first_element(bindNode,
                "{" XMPP_BIND_URI "}jid");
        if (jid)
        {
            return jw_dom_get_first_text(jid);
        }
    }

    return "";
}

static jw_dom_node *createPresence()
{
    jw_dom_ctx *domCtx;
    jw_dom_node *presDom;

    jw_dom_context_create(&domCtx, NULL);
    jw_dom_element_create(domCtx, XMPP_CLIENT_PRESENCE, &presDom, NULL);

    return presDom;
}

static void onBindElementsReceived(jw_event_data event, void *arg)
{
    UNUSED_PARAM(arg);

    jw_stream *stream = event->source;
    jw_dom_node **data = event->data;

    jw_event_unbind(
        jw_stream_event(stream, JW_STREAM_EVENT_ELEMRECV), 
        onBindElementsReceived);

    if (data)
    {
        const char *ename = jw_dom_get_ename(data[0]);
        if (jw_strcmp(ename, XMPP_CLIENT_IQ) == 0)
        {
            printf("received bind iq\n");
            jw_log(JW_LOG_INFO, "resource binding jid: [%s]",
                   findJidFromBind(data[0]));

            jw_stream_send(stream, createPresence(), NULL);
        }
    }
}

bool doBind(jw_stream *stream, jw_dom_node *node)
{
    if (findBind(node))
    { 
        jw_event_bind(
            jw_stream_event(stream, JW_STREAM_EVENT_ELEMRECV), 
            onBindElementsReceived, NULL, NULL);

        jw_err err;
        jw_dom_node *sendNode = createBind();
        if (!jw_stream_send(stream, sendNode, &err))
        {
            jw_log_err(JW_LOG_ERROR, &err, "could not send bind dom");
            return false;
        }

        return true;
    }

    return false;
}
