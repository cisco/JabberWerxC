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


#define SASL_EXTERNAL_NAME "EXTERNAL"


static bool _sasl_external_evaluate_start(
                        jw_sasl_mech_instance             *instance,
                        uint8_t                                *in,
                        size_t                                  in_len,
                        jw_sasl_mech_cdata_evaluate_complete_fn cb,
                        jw_err                                 *err)
{
    UNUSED_PARAM(in);
    UNUSED_PARAM(in_len);
    UNUSED_PARAM(err);

    JW_LOG_TRACE_FUNCTION("instance=%p", (void *)instance);

    cb(instance, NULL, 0, true, false, JW_SASL_ERR_NONE);

    return true;
}


JABBERWERX_API bool jw_sasl_mech_external_create(jw_htable     *config,
                                                 jw_sasl_mech **mech,
                                                 jw_err             *err)
{
    UNUSED_PARAM(config);

    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    jw_sasl_mech_fn_table fn_table = {
        .init_fn           = NULL,
        .clean_fn          = NULL,
        .evaluate_start_fn = _sasl_external_evaluate_start,
        .evaluate_step_fn  = NULL
    };

    return jw_sasl_mech_create(SASL_EXTERNAL_NAME, &fn_table, mech, err);
}
