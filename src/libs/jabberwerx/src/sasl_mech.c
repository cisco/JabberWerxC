/**
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

#include "include/sasl_int.h"
#include <jabberwerx/sasl_mech.h>
#include <jabberwerx/util/base64.h>
#include <jabberwerx/util/log.h>
#include <jabberwerx/util/mem.h>
#include <jabberwerx/util/str.h>
#include <assert.h>
#include <string.h>


static bool _default_evaluate_step(
                        jw_sasl_mech_instance *instance,
                        uint8_t              *in,
                        size_t                in_len,
                        jw_sasl_mech_cdata_evaluate_complete_fn cb,
                        jw_err               *err)
{
    UNUSED_PARAM(in_len);
    UNUSED_PARAM(err);

    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    if (in)
    {
        jw_data_free(in);
    }

    cb(instance, NULL, 0, false, true, JW_SASL_ERR_TEMPORARY_AUTH_FAILURE);

    return true;
}

bool _jw_sasl_mech_sasl_err_to_failure_node(
        jw_sasl_error sasl_err, jw_dom_ctx *ctx, jw_dom_node **node, jw_err *err)
{
    JW_LOG_TRACE_FUNCTION("sasl_err=%d", sasl_err);

    assert(ctx);
    assert(node);

    if (!jw_dom_element_create(ctx, SASL_FAILURE, node, err))
    {
        jw_log_err(JW_LOG_WARN, err, "unable to allocate sasl failure node");
        return false;
    }

    const char *reason_ename;
    switch (sasl_err)
    {
    case JW_SASL_ERR_ABORTED:
        reason_ename = SASL_ERR_ABORTED;
        break;
    case JW_SASL_ERR_ACCOUNT_DISABLED:
        reason_ename = SASL_ERR_ACCOUNT_DISABLED;
        break;
    case JW_SASL_ERR_CREDENTIALS_EXPIRED:
        reason_ename = SASL_ERR_CREDENTIALS_EXPIRED;
        break;
    case JW_SASL_ERR_ENCRYPTION_REQUIRED:
        reason_ename = SASL_ERR_ENCRYPTION_REQUIRED;
        break;
    case JW_SASL_ERR_INCORRECT_ENCODING:
        reason_ename = SASL_ERR_INCORRECT_ENCODING;
        break;
    case JW_SASL_ERR_INVALID_AUTHZID:
        reason_ename = SASL_ERR_INVALID_AUTHZID;
        break;
    case JW_SASL_ERR_INVALID_MECHANISM:
        reason_ename = SASL_ERR_INVALID_MECHANISM;
        break;
    case JW_SASL_ERR_MALFORMED_REQUEST:
        reason_ename = SASL_ERR_MALFORMED_REQUEST;
        break;
    case JW_SASL_ERR_MECHANISM_TOO_WEAK:
        reason_ename = SASL_ERR_MECHANISM_TOO_WEAK;
        break;
    case JW_SASL_ERR_NOT_AUTHORIZED:
        reason_ename = SASL_ERR_NOT_AUTHORIZED;
        break;
    case JW_SASL_ERR_TEMPORARY_AUTH_FAILURE:
        reason_ename = SASL_ERR_TEMPORARY_AUTH_FAILURE;
        break;
    default:
        reason_ename = SASL_ERR_TEMPORARY_AUTH_FAILURE;
        jw_log(JW_LOG_WARN, "unhandled sasl_err failure: %d; using '%s'",
               sasl_err, reason_ename);
    }

    jw_dom_node *reason_node;
    if (!jw_dom_element_create(ctx, reason_ename, &reason_node, err))
    {
        jw_log_err(JW_LOG_WARN, err, "unable to allocate sasl failure reason");
        return false;
    }

    if (!jw_dom_add_child(*node, reason_node, err))
    {
        // can't fail
        jw_log_err(JW_LOG_ERROR, err,
                   "unexpected error adding child to failure node");
        assert(false);
    }

    return true;
}

static jw_sasl_error _failure_node_to_sasl_err(jw_dom_node *node)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(node);

    if (JW_DOM_TYPE_ELEMENT != jw_dom_get_nodetype(node))
    {
        // this case is screened by the top-level evaluate function
        jw_log(JW_LOG_ERROR, "unexpected non-element failure node");
        assert(false);
    }

    jw_log_dom(JW_LOG_TRACE, node, "parsing failure node: ");

    jw_dom_node *reason_node = jw_dom_get_first_element(node, "{"SASL_URI"}");

    if (NULL == reason_node)
    {
        jw_log(JW_LOG_WARN, "failure node lacks reason element; assuming '%s'",
               SASL_ERR_TEMPORARY_AUTH_FAILURE_LOCALNAME);
        return JW_SASL_ERR_TEMPORARY_AUTH_FAILURE;
    }

    const char *reason = jw_dom_get_ename(reason_node);
    if (0 == jw_strcmp(SASL_ERR_NOT_AUTHORIZED, reason))
    {
        return JW_SASL_ERR_NOT_AUTHORIZED;
    }
    if (0 == jw_strcmp(SASL_ERR_TEMPORARY_AUTH_FAILURE, reason))
    {
        return JW_SASL_ERR_TEMPORARY_AUTH_FAILURE;
    }
    if (0 == jw_strcmp(SASL_ERR_ABORTED, reason))
    {
        return JW_SASL_ERR_ABORTED;
    }
    if (0 == jw_strcmp(SASL_ERR_ACCOUNT_DISABLED, reason))
    {
        return JW_SASL_ERR_ACCOUNT_DISABLED;
    }
    if (0 == jw_strcmp(SASL_ERR_CREDENTIALS_EXPIRED, reason))
    {
        return JW_SASL_ERR_CREDENTIALS_EXPIRED;
    }
    if (0 == jw_strcmp(SASL_ERR_ENCRYPTION_REQUIRED, reason))
    {
        return JW_SASL_ERR_ENCRYPTION_REQUIRED;
    }
    if (0 == jw_strcmp(SASL_ERR_INCORRECT_ENCODING, reason))
    {
        return JW_SASL_ERR_INCORRECT_ENCODING;
    }
    if (0 == jw_strcmp(SASL_ERR_INVALID_AUTHZID, reason))
    {
        return JW_SASL_ERR_INVALID_AUTHZID;
    }
    if (0 == jw_strcmp(SASL_ERR_INVALID_MECHANISM, reason))
    {
        return JW_SASL_ERR_INVALID_MECHANISM;
    }
    if (0 == jw_strcmp(SASL_ERR_MALFORMED_REQUEST, reason))
    {
        return JW_SASL_ERR_MALFORMED_REQUEST;
    }
    if (0 == jw_strcmp(SASL_ERR_MECHANISM_TOO_WEAK, reason))
    {
        return JW_SASL_ERR_MECHANISM_TOO_WEAK;
    }

    jw_log(JW_LOG_WARN, "unhandled reason: '%s'; using '%s'",
           reason,
           SASL_ERR_TEMPORARY_AUTH_FAILURE_LOCALNAME);
    return JW_SASL_ERR_TEMPORARY_AUTH_FAILURE;
}

static void _cdata_evaluate_complete(
                        jw_sasl_mech_instance *instance,
                        uint8_t              *out,
                        size_t                out_len,
                        bool                  needs_base64_encoding,
                        bool                  done,
                        jw_sasl_error         sasl_err)
{
    JW_LOG_TRACE_FUNCTION(
            "out_len=%zd; needs_base64_encoding=%d; done=%d; sasl_err=%d",
            out_len, needs_base64_encoding, done, sasl_err);

    assert(instance);
    assert(instance->cur_cb);

    jw_err      err;
    jw_dom_ctx  *out_ctx  = NULL;
    jw_dom_node *out_node = NULL;
    char       *lcl_text = NULL;
    char       *b64_text = NULL;
    if (!jw_dom_context_create(&out_ctx, &err))
    {
        jw_log_err(JW_LOG_WARN, &err, "unable to allocate sasl output context");
        goto _cdata_evaluate_complete_fail_label;
    }

    if (JW_SASL_ERR_NONE != sasl_err)
    {
        if (!_jw_sasl_mech_sasl_err_to_failure_node(
                        sasl_err, out_ctx, &out_node, &err))
        {
            // _sasl_err_to_failure_node logs an appropriate message on failure
            goto _cdata_evaluate_complete_fail_label;
        }
    }
    else if (1 == instance->step_count)
    {
        // construct a node of the form:
        // <auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>AGp1bGlldAByMG0zMG15cjBtMzA=</auth>
        // or <auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>=</auth>
        if (!jw_dom_element_create(out_ctx, SASL_AUTH, &out_node, &err))
        {
            jw_log_err(JW_LOG_WARN, &err, "unable to create sasl auth node");
            goto _cdata_evaluate_complete_fail_label;
        }

        const char *mech_name =
                jw_sasl_mech_get_name(jw_sasl_mech_instance_get_mech(instance));
        if (!jw_dom_set_attribute(out_node, "{}mechanism", mech_name, &err))
        {
            jw_log_err(JW_LOG_WARN, &err, "unable to set sasl auth node attr");
            goto _cdata_evaluate_complete_fail_label;
        }

        if (0 == out_len)
        {
            lcl_text = "=";
        }
    }
    else
    {
        // construct a node of the form:
        // <response xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>data</response>
        if (!jw_dom_element_create(out_ctx, SASL_RESPONSE, &out_node, &err))
        {
            jw_log_err(JW_LOG_WARN, &err,
                       "unable to create sasl response node");
            goto _cdata_evaluate_complete_fail_label;
        }
    }

    // construct text
    char *text;
    if (!needs_base64_encoding || 0 == out_len)
    {
        text = (NULL != lcl_text) ? lcl_text : (char *)out;
    }
    else
    {
        // jw_base64_encode null-terminates the output string
        size_t b64_text_len;
        if (!jw_base64_encode(
                out, out_len, &b64_text, &b64_text_len, &err))
        {
            jw_log_err(JW_LOG_WARN, &err, "could not base64 encode auth data");
            goto _cdata_evaluate_complete_fail_label;
        }

        text = b64_text;
    }

    // jw_dom_text_create dups the text, so we can destroy our copy
    if (NULL != text)
    {
        jw_dom_node *text_node;
        if (!jw_dom_text_create(out_ctx, text, &text_node, &err))
        {
            jw_log_err(JW_LOG_WARN, &err, "unable to create sasl auth node text");
            goto _cdata_evaluate_complete_fail_label;
        }

        if (!jw_dom_add_child(out_node, text_node, &err))
        {
            jw_log_err(JW_LOG_ERROR, &err,
                       "unexpected error while adding text node as child to"
                       " sasl response node");
            assert(false);
        }
    }

    goto _cdata_evaluate_complete_done_label;

_cdata_evaluate_complete_fail_label:
    out_node = NULL;
    done     = true;
    sasl_err = JW_SASL_ERR_TEMPORARY_AUTH_FAILURE;

_cdata_evaluate_complete_done_label:
    ; // where is the syntax error that this fixes?
    jw_sasl_mech_evaluate_complete_fn cb  = instance->cur_cb;
    void                             *arg = instance->cur_arg;
    instance->cur_cb  = NULL;
    instance->cur_arg = NULL;
    cb(instance, out_node, done, sasl_err, arg);

    if (NULL != b64_text)
    {
        jw_data_free(b64_text);
    }
    if (NULL != out_ctx)
    {
        jw_dom_context_destroy(out_ctx);
    }
    if (NULL != out)
    {
        jw_data_free(out);
    }
}

// verify a SASL mechanism name as per RFC 4422 section 3.1
static bool _verify_mech_name(const char *name)
{
    assert(name);
    
    const char *cur = name;

    while (*cur)
    {
        // sasl-mech = 1*20mech-char
        if (20 < (cur - name))
        {
            jw_log(JW_LOG_WARN, "name too long");
            return false;
        }

        // mech-char = UPPER-ALPHA / DIGIT / HYPHEN / UNDERSCORE
        char curChar = *cur;
        if (!('A' <= curChar && 'Z' >= curChar)
         && !('0' <= curChar && '9' >= curChar)
         && '-' != curChar
         && '_' != curChar)
        {
            jw_log(JW_LOG_WARN, "name character out of range: '%c'", curChar);
            return false;
        }

        ++cur;
    }

    // ensure there was at least one character
    return cur != name;
}


JABBERWERX_API bool jw_sasl_mech_create(
                        const char            *name,
                        jw_sasl_mech_fn_table *fn_table,
                        jw_sasl_mech          **mech,
                        jw_err                *err)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(name);
    assert(fn_table);
    assert(mech);

    if (! _verify_mech_name(name))
    {
        jw_log(JW_LOG_WARN, "invalid mechanism name: '%s'", name);
        JABBERWERX_ERROR(err, JW_ERR_INVALID_ARG);
        return false;
    }

    if (NULL == fn_table->evaluate_start_fn)
    {
        jw_log(JW_LOG_WARN,
               "cannot add mechanism with undefined evaluate_start_fn");
        JABBERWERX_ERROR(err, JW_ERR_INVALID_ARG);
        return false;
    }

    size_t mech_size = sizeof(struct _jw_sasl_mech);
    jw_sasl_mech *ret_mech = jw_data_malloc(mech_size);
    if (NULL == ret_mech)
    {
        jw_log_err(JW_LOG_WARN, err, "failed to allocate sasl mechanism");
        JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
        return false;
    }

    memset(ret_mech, 0, mech_size);

    ret_mech->name = name;
    ret_mech->fn_table = *fn_table;

    if (!fn_table->evaluate_step_fn)
    {
        jw_log(JW_LOG_DEBUG, "no step fn defined; using default");
        ret_mech->fn_table.evaluate_step_fn = _default_evaluate_step;
    }

    jw_log(JW_LOG_DEBUG, "allocated sasl mechanism %p", (void *)ret_mech);
    *mech = ret_mech;

    return true;
}

JABBERWERX_API bool jw_sasl_mech_copy(jw_sasl_mech  *mech,
                                      jw_sasl_mech **copy,
                                      jw_err       *err)
{
    JW_LOG_TRACE_FUNCTION("mech=%p", (void *)mech);

    return jw_sasl_mech_create(mech->name, &mech->fn_table, copy, err);
}

JABBERWERX_API void jw_sasl_mech_destroy(jw_sasl_mech *mech)
{
    JW_LOG_TRACE_FUNCTION("mech=%p", (void *)mech);

    jw_data_free(mech);
}

JABBERWERX_API const char* jw_sasl_mech_get_name(jw_sasl_mech *mech)
{
    JW_LOG_TRACE_FUNCTION("mech=%p", (void *)mech);

    assert(mech);
    return mech->name;
}

JABBERWERX_API bool jw_sasl_mech_instance_create(
                        jw_htable              *config,
                        jw_sasl_mech           *mech,
                        jw_sasl_mech_instance **instance,
                        jw_err                *err)
{
    JW_LOG_TRACE_FUNCTION("mech=%p", (void *)mech);

    assert(mech);
    assert(instance);

    size_t inst_size = sizeof(struct _jw_sasl_mech_instance);
    jw_sasl_mech_instance *ret_inst = jw_data_malloc(inst_size);
    if (NULL == ret_inst)
    {
        jw_log(JW_LOG_WARN, "failed to allocate sasl mechanism instance");
        JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
        return false;
    }

    memset(ret_inst, 0, inst_size);

    ret_inst->mech = mech;
    jw_sasl_mech_init_fn init_fn = mech->fn_table.init_fn;
    if (NULL != init_fn && !init_fn(ret_inst, config, err))
    {
        jw_log_err(JW_LOG_WARN, err, "mechanism init fn failed");
        jw_data_free(ret_inst);
        return false;
    }

    *instance = ret_inst;
    return true;
}

JABBERWERX_API void jw_sasl_mech_instance_destroy(
                        jw_sasl_mech_instance *instance)
{
    JW_LOG_TRACE_FUNCTION("instance=%p", (void *)instance);

    assert(instance);
    assert(instance->mech);

    jw_sasl_mech_clean_fn clean_fn = instance->mech->fn_table.clean_fn;
    if (clean_fn)
    {
        clean_fn(instance);
    }

    jw_data_free(instance);
}

JABBERWERX_API bool jw_sasl_mech_instance_evaluate(
                        jw_sasl_mech_instance *instance,
                        jw_dom_node           *in_auth_node,
                        jw_sasl_mech_evaluate_complete_fn cb,
                        void                 *arg,
                        jw_err               *err)
{
    JW_LOG_TRACE_FUNCTION("instance=%p", (void *)instance);

    assert(instance);
    assert(instance->mech);
    assert(cb);

    if (NULL != instance->cur_cb)
    {
        jw_log(JW_LOG_WARN,
               "call to %s while completion of previous call still pending",
               __func__);
        JABBERWERX_ERROR(err, JW_ERR_INVALID_STATE);
        return false;
    }

    bool     ret    = false;
    uint8_t *in     = NULL;
    size_t   in_len = 0;

    // if this is the final success or failure, call the complete fn directly
    if (NULL != in_auth_node)
    {
        const char *mech_name =
                jw_sasl_mech_get_name(jw_sasl_mech_instance_get_mech(instance));
        const char *ename = jw_dom_get_ename(in_auth_node);

        if (0 == jw_strcmp(ename, SASL_SUCCESS))
        {
            jw_log(JW_LOG_INFO, "%s authentication complete", mech_name);
            cb(instance, NULL, true, JW_SASL_ERR_NONE, arg);
            ret = true;
        }
        else if (0 == jw_strcmp(ename, SASL_FAILURE))
        {
            jw_log_dom(JW_LOG_INFO, in_auth_node,
                       "authentication failed (mechanism: '%s'): ", mech_name);
            cb(instance, in_auth_node, true,
               _failure_node_to_sasl_err(in_auth_node), arg);
            ret = true;
        }
        else if (0 == jw_strcmp(ename, SASL_CHALLENGE))
        {
            // don't log the actual challenge for security reasons
            jw_log(JW_LOG_DEBUG, "SASL challenge received");

            jw_err decode_err;

            // de-base64 the payload
            const char *encoded_text = jw_dom_get_first_text(in_auth_node);
            if (NULL != encoded_text
             && !jw_base64_decode(encoded_text, -1, &in, &in_len, &decode_err))
            {
                jw_log_err(JW_LOG_WARN, &decode_err,
                           "failed to decode challenge base64 text");

                jw_dom_ctx  *err_ctx  = NULL;
                jw_dom_node *err_node = NULL;

                if (!jw_dom_context_create(&err_ctx, &decode_err)
                 || !_jw_sasl_mech_sasl_err_to_failure_node(
                        JW_SASL_ERR_TEMPORARY_AUTH_FAILURE,
                        err_ctx, &err_node, &decode_err))
                {
                    jw_log_err(JW_LOG_WARN, &decode_err,
                               "could not create failure node");
                }

                cb(instance, err_node, true,
                   JW_SASL_ERR_TEMPORARY_AUTH_FAILURE, arg);
                if (NULL != err_ctx)
                {
                    jw_dom_context_destroy(err_ctx);
                }
                ret = true;
            }
        }
        else
        {
            jw_log(JW_LOG_WARN, "unhandled auth type: '%s'", ename);
            JABBERWERX_ERROR(err, JW_ERR_INVALID_ARG);
            return false;
        }
    }

    if (!ret)
    {
        instance->cur_cb  = cb;
        instance->cur_arg = arg;
        
        if (!(ret =
                (0 == instance->step_count++
                 ? instance->mech->fn_table.evaluate_start_fn
                 : instance->mech->fn_table.evaluate_step_fn)(
                      instance, in, in_len, _cdata_evaluate_complete, err)))
        {
            jw_data_free(in);
        }
    }

    return ret;
}

JABBERWERX_API jw_sasl_mech *jw_sasl_mech_instance_get_mech(
                        jw_sasl_mech_instance *instance)
{
    JW_LOG_TRACE_FUNCTION("instance=%p", (void *)instance);

    assert(instance);
    return instance->mech;
}

JABBERWERX_API void jw_sasl_mech_instance_set_data(
                        jw_sasl_mech_instance *instance, void *data)
{
    JW_LOG_TRACE_FUNCTION("instance=%p", (void *)instance);

    assert(instance);
    instance->data = data;
}

JABBERWERX_API void* jw_sasl_mech_instance_get_data(
                        jw_sasl_mech_instance *instance)
{
    JW_LOG_TRACE_FUNCTION("instance=%p", (void *)instance);

    assert(instance);
    return instance->data;
}
