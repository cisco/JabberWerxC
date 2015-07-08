/**
 * \file
 *
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

#include "../include/sasl_int.h"
#include <jabberwerx/sasl_mech.h>
#include <jabberwerx/util/log.h>
#include <jabberwerx/util/str.h>
#include <jabberwerx/client.h>
#include <string.h>


#define SASL_PLAIN_NAME "PLAIN"


static bool _sasl_plain_init(
      jw_sasl_mech_instance *instance, jw_htable *config, jw_err *err)
{
    JW_LOG_TRACE_FUNCTION("instance=%p", (void *)instance);

    if (NULL == config)
    {
        jw_log(JW_LOG_WARN, "config cannot be NULL");
        JABBERWERX_ERROR(err, JW_ERR_INVALID_ARG);
        return false;
    }

    jw_sasl_mech_instance_set_data(instance, config);

    return true;
}

static bool _sasl_plain_evaluate_start(
                        jw_sasl_mech_instance             *instance,
                        uint8_t                                *in,
                        size_t                                  in_len,
                        jw_sasl_mech_cdata_evaluate_complete_fn cb,
                        jw_err                                 *err)
{
    UNUSED_PARAM(in);
    UNUSED_PARAM(in_len);

    JW_LOG_TRACE_FUNCTION("instance=%p", (void *)instance);

    bool ret = false;

    jw_htable *config = jw_sasl_mech_instance_get_data(instance);

    jw_jid_ctx *jid_ctx_local = NULL;
    jw_jid     *jid           = NULL;
    uint8_t   *out           = NULL;

    jw_jid_ctx *jid_ctx = jw_htable_get(config,
                                             JW_CLIENT_CONFIG_JID_CONTEXT);
    if (NULL == jid_ctx)
    {
        if (!jw_jid_context_create(1, &jid_ctx_local, err))
        {
            jw_log_err(JW_LOG_WARN, err, "could not create local jid context");
            return false;
        }

        jid_ctx = jid_ctx_local;
    }

    const char *jid_str = jw_htable_get(config, JW_CLIENT_CONFIG_USERJID);
    if (NULL == jid_str)
    {
        jw_log(JW_LOG_WARN, "could not find user jid in config");
        JABBERWERX_ERROR(err, JW_ERR_INVALID_STATE);
        goto _sasl_plain_evaluate_start_fail_label;
    }

    if (!jw_jid_create(jid_ctx, jid_str, &jid, err))
    {
        jw_log_err(JW_LOG_WARN, err, "could not create local jid");
        goto _sasl_plain_evaluate_start_fail_label;
    }

    const char *user = jw_jid_get_localpart(jid);
    const char *pass = jw_htable_get(config, JW_CLIENT_CONFIG_USERPW);

    size_t user_len = jw_strlen(user);
    size_t pass_len = jw_strlen(pass);
    
    if (0 >= user_len || 0 >= pass_len)
    {
        jw_log(JW_LOG_WARN, "sasl plain: 0 length username or password");
        JABBERWERX_ERROR(err, JW_ERR_INVALID_STATE);
        goto _sasl_plain_evaluate_start_fail_label;
    }

    size_t out_len = user_len + pass_len + 2; // +2 for NULL separators
    out = jw_data_malloc(out_len);
    if (!out)
    {
        jw_log(JW_LOG_WARN, "could not create output buffer");
        JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
        goto _sasl_plain_evaluate_start_fail_label;
    }

    out[0] = '\0';
    strncpy((char *)out + 1, user, user_len);
    out[user_len + 1] = '\0';
    strncpy((char *)out + user_len + 2, pass, pass_len);

    // cb is responsible for destroying out
    cb(instance, out, out_len, true, false, JW_SASL_ERR_NONE);

    ret = true;

_sasl_plain_evaluate_start_fail_label:
    if (!ret && out)   { jw_data_free(out);                     }
    if (jid)           { jw_jid_destroy(jid);                   }
    if (jid_ctx_local) { jw_jid_context_destroy(jid_ctx_local); }

    return ret;
}


JABBERWERX_API bool jw_sasl_mech_plain_create(jw_htable     *config,
                                              jw_sasl_mech **mech,
                                              jw_err             *err)
{
    UNUSED_PARAM(config);

    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    jw_sasl_mech_fn_table fn_table = {
        .init_fn           = _sasl_plain_init,
        .clean_fn          = NULL,
        .evaluate_start_fn = _sasl_plain_evaluate_start,
        .evaluate_step_fn  = NULL
    };

    return jw_sasl_mech_create(SASL_PLAIN_NAME, &fn_table, mech, err);
}
