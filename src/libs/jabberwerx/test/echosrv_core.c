/**
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

#include "echosrv_core.h"
#include "stanza_defines.h"
#include "../src/include/stream_int.h"
#include <assert.h>
#include <string.h>
#include <jabberwerx/util/log.h>
#include <jabberwerx/jabberwerx.h>

/*
 * A small command protocol for remote control of a test echosrv
 *
 * messages of any type may contain a echo server command child:
 *     <echosrv-command xml:ns="http://cisco.com/echosrv>
 *        <cmd>ECHO|SEND|CLOSE</cmd>
 *        <additional-xml/>
 *     </echosrv-command>
 *
 *     ECHO - echosrv simply returns the message.  if no echo-srv-command
 *               element is specified, this is the default action.
 *     SEND - echosrv will send the given stanza to the message's from.
 *     CLOSE - forces echosrv to disconnect, sending optional given error stanza
 *             immediately before disconnect. (implemented in network layer)
 */
#define ECHOSRV_COMMAND_NS "http://cisco.com/echosrv"
#define ECHOSRV_COMMAND_LOCALNAME "echosrv-command"
#define ECHOSRV_COMMAND "{" ECHOSRV_COMMAND_NS "}" ECHOSRV_COMMAND_LOCALNAME
#define ECHOSRV_CMD_LOCALNAME "cmd"
#define ECHOSRV_CMD "{}" ECHOSRV_CMD_LOCALNAME


typedef enum
{
    EC_OPENING,
    EC_READY_TO_AUTH,
    EC_READY_TO_BIND,
    EC_STEADY,
    EC_RESPONSE_COMPLETE,
    EC_ERROR
} _echosrv_core_state;

typedef bool (*_serializer_writer_fn)(jw_serializer *ser,
                                      jw_dom_node   *node,
                                      jw_err             *err);

struct _jw_test_echosrv_core
{
    const char *streamId;
    const char *bindJID;
    jw_htable  *enabledFeatures;
    jw_htable  *requiredFeatures;

    _echosrv_core_state state;
    _echosrv_core_state prevstate;
    jw_parser          *parser;
    jw_err              parser_err;
    bool                reinit_parser;
    jw_serializer      *serial;
    struct evbuffer    *resp;

    _cmd_handler_fn cmd_handler_fn;
    void           *cmd_handler_arg;
};


static const char DEFAULT_STREAM_ID[] = "somerandomid";
static const char DEFAULT_BIND_JID[]  = "testuser@localhost/random-resource";


#define PUSH_ECHOSRV_CORE_NDC int _ndcDepth = _push_echosrv_core_ndc(__func__)
#define POP_ECHOSRV_CORE_NDC jw_log_pop_ndc(_ndcDepth)
static int _push_echosrv_core_ndc(const char *entrypoint)
{
    assert(entrypoint);
    return jw_log_push_ndc("echosrv_core entrypoint=%s", entrypoint);
}

static bool _reserve_htable_feature(jw_htable *htable, int key,
                                    jw_err *err)
{
    if (jw_htable_get_node(htable, (void *)(uintptr_t)key)) { return true; }
    return jw_htable_put(htable, (void *)(uintptr_t)key, NULL, NULL, err);
}

static bool _put_htable_feature(jw_htable *htable, int key, bool value,
                                jw_err *err)
{
    return jw_htable_put(htable, (const void *)(uintptr_t)key,
                         (void *)(uintptr_t)(false != value), NULL, err);
}

static bool _get_htable_feature(jw_htable *htable, int key)
{
    // booleanize the result (a value other than NULL or false returns true)
    return !!jw_htable_get(htable, (const void *)(uintptr_t)key);
}

static bool _serializer_write_end(jw_serializer *ser,
                                  jw_dom_node   *node,
                                  jw_err             *err)
{
    UNUSED_PARAM(node);
    return jw_serializer_write_end(ser, err);
}

static bool _create_cmd_node(jw_dom_ctx *ctx, const char *cmd,
                             jw_dom_node **cmd_node, jw_err *err)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(ctx);
    assert(cmd);

    jw_dom_node *parent, *child, *text;
    bool ret = jw_dom_element_create(ctx, ECHOSRV_COMMAND, &parent, err)
        && jw_dom_element_create(ctx, ECHOSRV_CMD, &child, err)
        && jw_dom_text_create(ctx, cmd, &text, err)
        && jw_dom_add_child(child, text, err)
        && jw_dom_add_child(parent, child, err);

    if (ret)
    {
        *cmd_node = parent;
    }

    return ret;
}

// finds the command node and gets references to the data.
static void _extract_cmd_info(
        jw_dom_node *cmd_node, const char **cmd, jw_dom_node **cmd_data)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(cmd_node);
    assert(cmd);
    assert(cmd_data);

    *cmd      = NULL;
    *cmd_data = NULL;

    jw_dom_node *child = jw_dom_get_first_child(cmd_node);
    while (child)
    {
        jw_log_dom(JW_LOG_DEBUG, child, "checking child node for commands: ");

        if (0 == jw_strcmp(jw_dom_get_ename(child), ECHOSRV_CMD))
        {
            *cmd = jw_dom_get_first_text(child);
        }
        else
        {
            *cmd_data = child;
        }
        child = jw_dom_get_sibling(child);
    }
}

static jw_dom_node *_process_command(
        jw_test_echosrv_core echosrv_core, jw_dom_node *stanza, const char *cmd,
        jw_dom_node *cmd_data, jw_err *err)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(echosrv_core);

    if (!cmd || (0 == strcmp(JW_ECHOSRV_CMD_ECHO, cmd)))
    {
        if (stanza)
        {
            const char *to   = jw_dom_get_attribute(stanza, "{}to");
            const char *from = jw_dom_get_attribute(stanza, "{}from");

            // switch to/from
            if (!jw_dom_set_attribute(stanza, "{}to", from, err)
             || !jw_dom_set_attribute(stanza, "{}from", to, err))
            {
                return NULL;
            }
        }
        return stanza;
    }
    else if (cmd_data && 0 == strcmp(JW_ECHOSRV_CMD_SEND, cmd))
    {
        return cmd_data;
    }
    else if (echosrv_core->cmd_handler_fn)
    {
        // see if the external handler can handle it
        jw_dom_node *reply;
        if (echosrv_core->cmd_handler_fn(
             stanza, cmd, cmd_data, &reply, echosrv_core->cmd_handler_arg, err))
        {
            return reply;
        }
    }

    return NULL;
}

// returns the appropriate response.  if a command node found, detaches
// from the stanza
static jw_dom_node *_get_response(
        jw_test_echosrv_core echosrv_core, jw_dom_node *stanza, jw_err *err)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(echosrv_core);

    jw_dom_node *cmd_node = jw_dom_get_first_element(stanza, ECHOSRV_COMMAND);
    const char  *cmd      = NULL;
    jw_dom_node *cmd_data = NULL;

    if (cmd_node)
    {
        _extract_cmd_info(cmd_node, &cmd, &cmd_data);
        jw_dom_detach(cmd_node);
    }

    return _process_command(echosrv_core, stanza, cmd, cmd_data, err);
}

#define _write_resp(echosrv_core, element, writer_fn, err) \
        _write_resp_int(echosrv_core, element, writer_fn, #writer_fn, err)
static bool _write_resp_int(jw_test_echosrv_core echosrv_core,
                            jw_dom_node *element,
                            _serializer_writer_fn writer_fn,
                            const char *writer_name, jw_err *err)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;
    assert(echosrv_core);

    jw_log_dom(JW_LOG_DEBUG, element,
               "writing data (%s) to client: ", writer_name);

    if (!writer_fn(echosrv_core->serial, element, err))
    {
        jw_log(JW_LOG_DEBUG, "failed to write data to client");
        return false;
    }

    return true;
}

// parser will continue to fire these events while there is data in its buffer
// (multiple nodes within one buffer).  Want to ignore any elements after
// we we receive root end <stream:stream/>.  Mid parse error could have
// happened along some event chain.  Use stream->err in both cases and always
// continue if set.
static void _parser_open_cb(jw_event_data evt, void *arg)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    jw_test_echosrv_core echosrv_core = arg;
    jw_dom_node         *root         = evt->data;

    assert(echosrv_core);
    assert(root);

    if (EC_ERROR == echosrv_core->state)
    {
        jw_log(JW_LOG_DEBUG, "in error state; not processing open event");
        goto _parser_open_cb_done_label;
    }

    jw_log_dom(JW_LOG_DEBUG, root, "opening root element: ");

    jw_err *err = &echosrv_core->parser_err;
    jw_dom_node *ret_root = _get_response(echosrv_core, root, err);

    if (!ret_root)
    {
        goto _parser_open_cb_fail_label;
    }

    if (!jw_dom_get_attribute(ret_root, "{}rid"))
    {
        // handle stream
        if (!jw_dom_set_attribute(ret_root, "{}id", echosrv_core->streamId, err))
        {
            goto _parser_open_cb_fail_label;
        }
    }
    else
    {
        // handle bosh
        bool failed;
        if (EC_OPENING != echosrv_core->state)
        {
            failed = !jw_dom_set_attribute(ret_root, "{}rid", NULL, err)
                  || !jw_dom_set_attribute(ret_root, "{}sid", NULL, err)
                  || !jw_dom_set_attribute(ret_root, "{urn:xmpp:xbosh}restart",
                                                              NULL, err);
        }
        else
        {
            const char *rid = jw_dom_get_attribute(ret_root, "{}rid");
            const char *id  = jw_dom_get_attribute(ret_root, "{}id");

            failed =
                !jw_dom_set_attribute(ret_root, "{}ack",        rid,    err)
             || !jw_dom_set_attribute(ret_root, "{}rid",        NULL,   err)
             || !jw_dom_set_attribute(ret_root, "{}authid",     id,     err)
             || !jw_dom_set_attribute(ret_root, "{}sid",        id,     err)
             || !jw_dom_set_attribute(ret_root, "{}id",         NULL,   err)
             || !jw_dom_set_attribute(ret_root, "{}inactivity", "60",   err)
             || !jw_dom_set_attribute(ret_root, "{}polling",    "5",    err)
             || !jw_dom_set_attribute(ret_root, "{}requests",   "2",    err)
             || !jw_dom_set_attribute(ret_root, "{}secure",     "true", err)
             || !jw_dom_set_attribute(ret_root, "{}ver",        "1.8",  err)
             || !jw_dom_set_attribute(ret_root, "{}wait",       "30",   err)
             || !jw_dom_set_attribute(ret_root, "{urn:xmpp:xbosh}version",
                                                                "1.0",  err);
        }

        if (failed)
        {
            goto _parser_open_cb_fail_label;
        }
    }

    if (!_write_resp(echosrv_core, ret_root, jw_serializer_write_start, err))
    {
        goto _parser_open_cb_fail_label;
    }

    if (EC_OPENING       != echosrv_core->state
     && EC_READY_TO_BIND != echosrv_core->state)
    {
        // don't add a features element
        goto _parser_open_cb_done_label;
    }

    jw_dom_node *features;
    jw_dom_ctx  *ctx = jw_dom_get_context(root);
    if (!jw_dom_element_create(ctx,
                               "{http://etherx.jabber.org/streams}features",
                               &features,
                               err))
    {
        goto _parser_open_cb_fail_label;
    }

    if (EC_OPENING == echosrv_core->state)
    {
        jw_dom_node *mechanisms, *mechanism, *plain;

        jw_log(JW_LOG_DEBUG, "sending features/sasl/plain");

        if (!jw_dom_element_create(ctx, XMPP_SASL_MECHS, &mechanisms, NULL)
         || !jw_dom_element_create(ctx, XMPP_SASL_MECH, &mechanism, NULL)
         || !jw_dom_text_create(ctx, XMPP_SASL_PLAIN, &plain, NULL)
         || !jw_dom_add_child(mechanism, plain, NULL)
         || !jw_dom_add_child(mechanisms, mechanism, NULL)
         || !jw_dom_add_child(features, mechanisms, NULL))
        {
            goto _parser_open_cb_fail_label;
        }

        echosrv_core->state = EC_READY_TO_AUTH;
    }
    else if (EC_READY_TO_BIND == echosrv_core->state)
    {
        jw_dom_node *bind, *session;

        jw_log(JW_LOG_DEBUG, "sending features/bind");
        if (!jw_dom_element_create(ctx, XMPP_BIND, &bind, NULL)
         || !jw_dom_add_child(features, bind, NULL)
         || !jw_dom_element_create(ctx, XMPP_SESSION, &session, NULL)
         || !jw_dom_add_child(features, session, NULL))
        {
            goto _parser_open_cb_fail_label;
        }

        if (_get_htable_feature(echosrv_core->enabledFeatures,
                                JW_ECHOSRV_FEATURE_SM))
        {
            jw_dom_node *sm;

            if (!jw_dom_element_create(ctx, XMPP_SM, &sm, NULL)
             || !jw_dom_add_child(features, sm, NULL))
            {
                goto _parser_open_cb_fail_label;
            }
        }

        echosrv_core->state = EC_STEADY;
    }

    if (!jw_dom_add_child(ret_root, features, NULL)
     || !_write_resp(echosrv_core, features, jw_serializer_write, err))
    {
        goto _parser_open_cb_fail_label;
    }

    goto _parser_open_cb_done_label;

_parser_open_cb_fail_label:
    jw_log(JW_LOG_DEBUG, "setting state to EC_ERROR");
    echosrv_core->state = EC_ERROR;
_parser_open_cb_done_label:
    evt->handled = true;
    return;
}

static void _parser_closed_cb(jw_event_data evt, void *arg)
{
    UNUSED_PARAM(evt);

    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    jw_test_echosrv_core echosrv_core = arg;

    assert(echosrv_core);

    if (EC_ERROR == echosrv_core->state)
    {
        jw_log(JW_LOG_DEBUG, "in error state; not processing close event");
        return;
    }

    if (EC_RESPONSE_COMPLETE == echosrv_core->state)
    {
        jw_log(JW_LOG_DEBUG,
               "response already complete; not processing close event");
    }
    else
    {
        jw_log(JW_LOG_DEBUG, "closing root element");
        if (!_write_resp(echosrv_core, NULL, _serializer_write_end,
                         &echosrv_core->parser_err))
        {
            jw_log(JW_LOG_DEBUG, "failed to close root element");
        }
    }

    echosrv_core->reinit_parser = true;
    evt->handled = true;
}

static void _parser_element_cb(jw_event_data evt, void *arg)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    jw_test_echosrv_core echosrv_core = arg;
    jw_dom_node         *element      = evt->data;
    char                *dstr         = NULL;

    assert(echosrv_core);

    if (EC_ERROR == echosrv_core->state)
    {
        jw_log(JW_LOG_DEBUG, "in error state; not processing element");
        goto _parser_element_cb_done_label;
    }

    if (!element || JW_DOM_TYPE_ELEMENT != jw_dom_get_nodetype(element))
    {
        goto _parser_element_cb_done_label;
    }

    jw_log_dom(JW_LOG_DEBUG, element, "handling element: ");

    jw_err *err = &echosrv_core->parser_err;
    if (!jw_serialize_xml(element, &dstr, NULL, err))
    {
        goto _parser_element_cb_fail_label;
    }

    jw_dom_ctx *ctx = jw_dom_get_context(element);
    if (EC_RESPONSE_COMPLETE == echosrv_core->state)
    {
        // skip element
    }
    else if (0 == strcmp(jw_dom_get_ename(element), ECHOSRV_COMMAND))
    {
        const char  *cmd      = NULL;
        jw_dom_node *cmd_data = NULL;

        _extract_cmd_info(element, &cmd, &cmd_data);

        if (_process_command(echosrv_core, NULL, cmd, cmd_data, err))
        {
            // replace serialization so far and ensure no more serialization
            // will take place
            char  *xml = NULL;
            size_t xmllen;

            _log_evbuffer(JW_LOG_DEBUG, echosrv_core->resp,
                          "overwriting pending response: ");

            if (0 != evbuffer_drain(echosrv_core->resp,
                                    evbuffer_get_length(echosrv_core->resp))
             || !jw_serialize_xml(cmd_data, &xml, &xmllen, err)
             || 0 != evbuffer_add(echosrv_core->resp, xml, xmllen))
            {
                goto _parser_element_cb_fail_label;
            }
            echosrv_core->prevstate = echosrv_core->state;
            echosrv_core->state     = EC_RESPONSE_COMPLETE;

            if (xml)
            {
                jw_data_free(xml);
            }
        }
    }
    else if (EC_READY_TO_AUTH == echosrv_core->state
     && 0 == strncmp("<auth", dstr, 5))
    {
        jw_dom_node *success;

        // return auth success
        if (!jw_dom_element_create(ctx, XMPP_SASL_SUCCESS, &success, err)
         || !_write_resp(echosrv_core, success, jw_serializer_write, err))
        {
            goto _parser_element_cb_fail_label;
        }

        // indicate that we should reset the parser at the top level
        echosrv_core->reinit_parser = true;
        echosrv_core->state = EC_READY_TO_BIND;
    }
    else if (0 == strcmp(jw_dom_get_ename(element), XMPP_CLIENT_IQ)
          && jw_dom_get_first_element(element, XMPP_BIND))
    {
        // return bind result, use <resource/> if provided, otherwise use a
        // default
        jw_dom_node *result, *jidchild;
        jw_jid_ctx *jidCtx = NULL;
        jw_jid *bindJID;

        if (!jw_dom_clone(element, true, &result, err)
         || !jw_dom_set_attribute(result, "{}type", "result", err)
         || !jw_dom_element_create(ctx, "{" XMPP_BIND_URI "}jid", &jidchild, err)
         || !jw_dom_add_child(jw_dom_get_first_element(result, XMPP_BIND), jidchild, err)
         || !jw_jid_context_create(0, &jidCtx, err)
         || !jw_jid_create(jidCtx, echosrv_core->bindJID, &bindJID, err))
        {
            if (jidCtx) { jw_jid_context_destroy(jidCtx); }
            goto _parser_element_cb_fail_label;
        }

        jw_dom_node *resourceChild = jw_dom_get_first_element(
                jw_dom_get_first_element(result, XMPP_BIND),
                "{" XMPP_BIND_URI "}resource");
        if (resourceChild)
        {
            if (!jw_jid_create_by_parts(jidCtx,
                                        jw_jid_get_localpart(bindJID),
                                        jw_jid_get_domain(bindJID),
                                        jw_dom_get_first_text(resourceChild),
                                        &bindJID, err))
            {
                jw_jid_context_destroy(jidCtx);
                goto _parser_element_cb_fail_label;
            }

            // don't echo <resource/>
            jw_dom_detach(resourceChild);
        }

        jw_dom_node *txtchild;
        if (!jw_dom_text_create(ctx, jw_jid_get_full(bindJID), &txtchild, err)
         || !jw_dom_add_child(jidchild, txtchild, err)
         || !_write_resp(echosrv_core, result, jw_serializer_write, err))
        {
            jw_jid_context_destroy(jidCtx);
            goto _parser_element_cb_fail_label;
        }

        jw_jid_context_destroy(jidCtx);
    }
    else if (0 == strcmp(jw_dom_get_ename(element), XMPP_SM_ENABLE))
    {
        jw_dom_node *enabled;

        // return 'enabled' sm element
        if (!jw_dom_element_create(ctx, XMPP_SM_ENABLED, &enabled, err)
         || !_write_resp(echosrv_core, enabled, jw_serializer_write, err))
        {
            goto _parser_element_cb_fail_label;
        }
    }
    else
    {
        jw_dom_node *response = _get_response(echosrv_core, element, err);

        if (!response)
        {
            goto _parser_element_cb_fail_label;
        }

        if (!_write_resp(echosrv_core, response, jw_serializer_write, err))
        {
            goto _parser_element_cb_fail_label;
        }
    }

    goto _parser_element_cb_done_label;

_parser_element_cb_fail_label:
    jw_log(JW_LOG_DEBUG, "setting state to EC_ERROR");
    echosrv_core->state = EC_ERROR;
_parser_element_cb_done_label:
    if (dstr)
    {
        jw_data_free(dstr);
    }
    evt->handled = true;
}

static void _clean_parser(jw_test_echosrv_core echosrv_core)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(echosrv_core);

    if (echosrv_core->parser)
    {
        jw_parser_destroy(echosrv_core->parser);
        echosrv_core->parser = NULL;
    }

    if (echosrv_core->serial)
    {
        jw_serializer_destroy(echosrv_core->serial);
        echosrv_core->serial = NULL;
    }

    if (echosrv_core->resp)
    {
        evbuffer_free(echosrv_core->resp);
        echosrv_core->resp = NULL;
    }

    echosrv_core->reinit_parser = false;
}

static bool _init_parser(jw_test_echosrv_core echosrv_core, jw_err *err)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    jw_log(JW_LOG_DEBUG, "initializing echosrv core parser");

    _clean_parser(echosrv_core);
    assert(!echosrv_core->parser);
    assert(!echosrv_core->resp);

    if (!(echosrv_core->resp = evbuffer_new()))
    {
        JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
        return false;
    }

    return jw_serializer_create(echosrv_core->resp, &echosrv_core->serial, err)
     && jw_parser_create(true, &echosrv_core->parser, err)
     && jw_event_bind(jw_parser_event(echosrv_core->parser,
                                      JW_PARSER_EVENT_OPEN),
                      _parser_open_cb, echosrv_core, err)
     && jw_event_bind(jw_parser_event(echosrv_core->parser,
                                      JW_PARSER_EVENT_CLOSED),
                      _parser_closed_cb, echosrv_core, err)
     && jw_event_bind(jw_parser_event(echosrv_core->parser,
                                      JW_PARSER_EVENT_ELEMENT),
                      _parser_element_cb, echosrv_core, err);
}


///////////////////////////////////////////////////////
// public API
//

bool _jw_test_echosrv_core_create(jw_test_echosrv_core *ret_echosrv_core,
                                  jw_err               *err)
{
    PUSH_ECHOSRV_CORE_NDC;
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(ret_echosrv_core);

    bool retval = false;

    jw_test_echosrv_core echosrv_core =
            jw_data_calloc(1, sizeof(struct _jw_test_echosrv_core));
    if (!echosrv_core)
    {
        JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
        goto jw_test_echosrv_core_create_done_label;
    }

    if (!jw_htable_create(0, jw_int_hashcode, jw_int_compare,
                          &echosrv_core->enabledFeatures, err)
     || !jw_htable_create(0, jw_int_hashcode, jw_int_compare,
                          &echosrv_core->requiredFeatures, err)
     || !_init_parser(echosrv_core, err))
    {
        goto jw_test_echosrv_core_create_done_label;
    }

    echosrv_core->streamId = DEFAULT_STREAM_ID;
    echosrv_core->bindJID  = DEFAULT_BIND_JID;

    *ret_echosrv_core = echosrv_core;
    retval = true;

jw_test_echosrv_core_create_done_label:
    if (!retval && echosrv_core)
    {
        _jw_test_echosrv_core_destroy(echosrv_core);
    }
    POP_ECHOSRV_CORE_NDC;
    return retval;
}

void _jw_test_echosrv_core_destroy(jw_test_echosrv_core echosrv_core)
{
    PUSH_ECHOSRV_CORE_NDC;
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    _clean_parser(echosrv_core);

    if (echosrv_core->enabledFeatures)
    {
        jw_htable_destroy(echosrv_core->enabledFeatures);
    }
    if (echosrv_core->requiredFeatures)
    {
        jw_htable_destroy(echosrv_core->requiredFeatures);
    }
    
    jw_data_free(echosrv_core);

    POP_ECHOSRV_CORE_NDC;
}

void _jw_test_echosrv_core_set_cmd_handler(jw_test_echosrv_core echosrv_core,
                                           _cmd_handler_fn      handler_fn,
                                           void                *arg)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(echosrv_core);

    echosrv_core->cmd_handler_fn  = handler_fn;
    echosrv_core->cmd_handler_arg = arg;
}

bool _jw_test_echosrv_core_feature_ctrl(
                        jw_test_echosrv_core     echosrv_core,
                        jw_test_echosrv_features enabled_features_mask,
                        jw_test_echosrv_features required_features_mask,
                        jw_err                  *err)
{
    PUSH_ECHOSRV_CORE_NDC;
    JW_LOG_TRACE_FUNCTION(
            "enabled_features_mask=0x%x; required_features_mask=0x%x",
            enabled_features_mask, required_features_mask);

    assert(echosrv_core);

    if (!_reserve_htable_feature(echosrv_core->enabledFeatures, JW_ECHOSRV_FEATURE_SM, err)
     || !_reserve_htable_feature(echosrv_core->enabledFeatures, JW_ECHOSRV_FEATURE_SM_RESUME, err)
     || !_reserve_htable_feature(echosrv_core->requiredFeatures, JW_ECHOSRV_FEATURE_SM, err)
     || !_reserve_htable_feature(echosrv_core->requiredFeatures, JW_ECHOSRV_FEATURE_SM_RESUME, err))
    {
        POP_ECHOSRV_CORE_NDC;
        return false;
    }

    if (!_put_htable_feature(echosrv_core->enabledFeatures, JW_ECHOSRV_FEATURE_SM,
            (enabled_features_mask & JW_ECHOSRV_FEATURE_SM), err)
     || !_put_htable_feature(echosrv_core->enabledFeatures, JW_ECHOSRV_FEATURE_SM_RESUME,
            (enabled_features_mask & JW_ECHOSRV_FEATURE_SM_RESUME), err)
     || !_put_htable_feature(echosrv_core->requiredFeatures, JW_ECHOSRV_FEATURE_SM,
            (required_features_mask & JW_ECHOSRV_FEATURE_SM), err)
     || !_put_htable_feature(echosrv_core->requiredFeatures, JW_ECHOSRV_FEATURE_SM_RESUME,
            (required_features_mask & JW_ECHOSRV_FEATURE_SM_RESUME), err))
    {
        jw_log_err(JW_LOG_ERROR, err,
                   "unexpected error while populating features properties");
        assert(false);
    }

    POP_ECHOSRV_CORE_NDC;
    return true;
}

void _jw_test_echosrv_core_set_stream_id(jw_test_echosrv_core echosrv_core,
                                         const char          *streamId)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(echosrv_core);
    assert(streamId);
    assert(0 < strlen(streamId));

    echosrv_core->streamId = streamId;
}

void _jw_test_echosrv_core_set_bind_jid(jw_test_echosrv_core echosrv_core,
                                        const char          *bind_jid)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(echosrv_core);
    assert(bind_jid);
    assert(strlen(bind_jid) > 0);

    echosrv_core->bindJID = bind_jid;
}

bool _jw_test_echosrv_core_submit(
                        jw_test_echosrv_core echosrv_core,
                        struct evbuffer     *req,
                        struct evbuffer     *resp,
                        jw_err              *err)
{
    PUSH_ECHOSRV_CORE_NDC;
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(echosrv_core);
    assert(req);

    // parse request and respond to contained elements
    if (EC_ERROR == echosrv_core->state)
    {
        jw_log(JW_LOG_DEBUG, "in error state; not parsing submission");
        JABBERWERX_ERROR(err, JW_ERR_INVALID_STATE);
        goto jw_test_echosrv_core_submit_fail_label;
    }

    // we're starting a new root element -- reset the parser
    if (echosrv_core->reinit_parser && !_init_parser(echosrv_core, err))
    {
        goto jw_test_echosrv_core_submit_fail_label;
    }

    // all parser events for the req buffer will be fired and processed before
    // the next line returns
    _log_evbuffer(JW_LOG_DEBUG, req, "parsing");
    if (!jw_parser_process(echosrv_core->parser, req, err))
    {
        goto jw_test_echosrv_core_submit_fail_label;
    }

    if (JW_ERR_NONE != echosrv_core->parser_err.code)
    {
        if (err)
        {
            *err = echosrv_core->parser_err;
        }
        goto jw_test_echosrv_core_submit_fail_label;
    }

    _log_evbuffer(JW_LOG_DEBUG, echosrv_core->resp, "outputting");

    if (0 != (resp
              ? evbuffer_add_buffer(resp, echosrv_core->resp)
              : evbuffer_drain(echosrv_core->resp,
                               evbuffer_get_length(echosrv_core->resp))))
    {
        JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
        goto jw_test_echosrv_core_submit_fail_label;
    }

    if (EC_RESPONSE_COMPLETE == echosrv_core->state)
    {
        echosrv_core->state = echosrv_core->prevstate;
    }

    POP_ECHOSRV_CORE_NDC;
    return true;

jw_test_echosrv_core_submit_fail_label:
    POP_ECHOSRV_CORE_NDC;
    return false;
}

bool _jw_test_echosrv_core_add_command(jw_dom_node *element,
                                       const char  *cmd,
                                       jw_dom_node *cmd_data,
                                       jw_err      *err)
{
    PUSH_ECHOSRV_CORE_NDC;
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    if (!element || !cmd || !cmd[0])
    {
        goto jw_test_echosrv_core_add_command_done_label;
    }

    jw_dom_ctx  *ctx = jw_dom_get_context(element);
    jw_dom_node *cmd_node;

    if (!_create_cmd_node(ctx, cmd, &cmd_node, err))
    {
        goto jw_test_echosrv_core_add_command_fail_label;
    }

    if (cmd_data)
    {
        jw_dom_node *cmd_data_cpy;
        if (!jw_dom_import(ctx, cmd_data, true, &cmd_data_cpy, err)
         || !jw_dom_add_child(cmd_node, cmd_data_cpy, err))
        {
            goto jw_test_echosrv_core_add_command_fail_label;
        }
    }

    if (!jw_dom_add_child(element, cmd_node, err))
    {
        goto jw_test_echosrv_core_add_command_fail_label;
    }

jw_test_echosrv_core_add_command_done_label:
    POP_ECHOSRV_CORE_NDC;
    return true;

jw_test_echosrv_core_add_command_fail_label:
    POP_ECHOSRV_CORE_NDC;
    return false;
}

void _jw_test_echosrv_core_remove_command(jw_dom_node *element)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(element);

    jw_dom_node *cmd_node = jw_dom_get_first_element(element, ECHOSRV_COMMAND);
    if (cmd_node)
    {
        jw_dom_detach(cmd_node);
    }
}
