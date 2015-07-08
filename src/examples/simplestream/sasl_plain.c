/**
 * \file
 * sasl_plain.c
 *
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2011 Cisco Systems, Inc.  All Rights Reserved.
 */

#include "sasl_plain.h"
#include "simplestream_defines.h"
#include "simplestream_utils.h"

#include <string.h>
#include <stdio.h>

#include <jabberwerx/util/log.h>
#include <jabberwerx/util/str.h>
#include <jabberwerx/util/base64.h>
#include <jabberwerx/jid.h>


static bool findPlainAuth(jw_dom_node *features)
{
    jw_dom_node *mechanisms;
    jw_dom_node *mech;

    mechanisms = jw_dom_get_first_element(features, XMPP_SASL_MECHS);
    if (!mechanisms)
    {
        return false;
    }

    mech = jw_dom_get_first_child(mechanisms);
    while (mech)
    {
        const char *mechValue = jw_dom_get_first_text(mech);
        if (mechValue && strcmp(mechValue, "PLAIN") == 0)
        {
            return true;
        }

        mech = jw_dom_get_sibling(mech);
    }

    return false;
}

static void createPlainAuthText(const char *username,
                                const char *password,
                                char **authStr,
                                size_t *authStrLen)
{
    size_t usernameLength = jw_strlen(username);
    size_t passwordLength = jw_strlen(password);
    char *tmpStr;
    size_t tmpStrLen;

    tmpStrLen = usernameLength+passwordLength+2;
    tmpStr = (char*)jw_data_malloc(tmpStrLen);

    tmpStr[0] = '\0';
    strncpy(tmpStr+1, username, usernameLength);

    tmpStr[usernameLength+1] = '\0';
    strncpy(tmpStr+usernameLength+2, password, passwordLength);

    jw_base64_encode((const uint8_t*)tmpStr, tmpStrLen, authStr, authStrLen, NULL);

    jw_data_free(tmpStr);
}

static jw_dom_node *createPlainAuth(jw_htable *config)
{
    jw_dom_ctx *domCtx;
    jw_dom_node *authDom;

    jw_dom_node *authText;
    char *authStr;
    size_t authStrLen;

    const char* username = (const char*)jw_htable_get(config,
            JW_STREAM_CONFIG_USERJID);
    const char* password = (const char*)jw_htable_get(config,
            JW_STREAM_CONFIG_USERPW);

    jw_jid_ctx *jid_ctx;
    jw_jid *jid;
    jw_jid_context_create(1, &jid_ctx, NULL);
    jw_jid_create(jid_ctx, username, &jid, NULL);

    username = jw_jid_get_localpart(jid);

    jw_dom_context_create(&domCtx, NULL);

    jw_dom_element_create(domCtx, XMPP_SASL_AUTH, &authDom, NULL);
    jw_dom_put_namespace(authDom, "", XMPP_SASL_URI, NULL);
    jw_dom_set_attribute(authDom, "{}mechanism", "PLAIN", NULL);

    createPlainAuthText(username, password, &authStr, &authStrLen);

    jw_dom_text_create(domCtx, authStr, &authText, NULL);
    jw_dom_add_child(authDom, authText, NULL);

    jw_data_free(authStr);
    jw_jid_context_destroy(jid_ctx);

    return authDom;
}

static void onSaslPlainElementsReceived(jw_event_data event, void *arg)
{
    UNUSED_PARAM(arg);

    jw_stream *stream = event->source;
    jw_dom_node **data = event->data;

    jw_event_unbind(
        jw_stream_event(stream, JW_STREAM_EVENT_ELEMRECV), 
        onSaslPlainElementsReceived);

    if (data)
    {
        const char *ename = jw_dom_get_ename(data[0]);
        if (jw_strcmp(ename, XMPP_SASL_SUCCESS) == 0)
        {
            jw_err err;
            printf("authentication successful\n");
            if (!jw_stream_reopen(stream, &err))
            {
                jw_log_err(JW_LOG_ERROR, &err, "could not reopen stream");
                jw_stream_close(stream, err.code);
            }
        }
    }
}

bool doSaslPlain(jw_stream *stream, jw_dom_node *node, jw_htable *config)
{
    if (findPlainAuth(node))
    { 
        jw_event_bind(
            jw_stream_event(stream, JW_STREAM_EVENT_ELEMRECV), 
            onSaslPlainElementsReceived, NULL, NULL);

        jw_err err;
        jw_dom_node *sendNode = createPlainAuth(config);
        if (!jw_stream_send(stream, sendNode, &err))
        {
            jw_log_err(JW_LOG_ERROR, &err, "could not send sasl dom");
            return false;
        }

        return true;
    }

    return false;
}

