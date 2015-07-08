/**
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <jabberwerx/util/log.h>
#include "../include/utils.h"

#define MS_PER_SECOND 1000

/**
 * converts a seconds.milliseconds double to time_t milliseconds.
 */
uint32_t jw_utils_dtoms(double dbl)
{
    JW_LOG_TRACE_FUNCTION("dbl=%f", dbl);

    uint64_t ret;
    uint32_t msecs;

    if (dbl < 0.001)
    {
        return 0;
    }

    if (dbl < UINT32_MAX)
    {
        ret = (uint32_t)dbl; // seconds
        msecs = (uint32_t)((dbl - ret) * MS_PER_SECOND);
        ret = ret * MS_PER_SECOND + msecs;
        if (ret <= UINT32_MAX)
        {
            return (uint32_t)ret;
        }
    }

    jw_log(JW_LOG_WARN,
           "overflow attempting to convert double '%f' to milliseconds", dbl);
    return UINT32_MAX;
}

bool jw_utils_config_get_double(jw_htable *config,
                                const char     *key,
                                double          default_val,
                                double         *val,
                                jw_err         *err)
{
    JW_LOG_TRACE_FUNCTION("key='%s'; default=%f%s",
                          key, default_val,
                          val ? "" : "; validating only");

    double ret = default_val;

    if (config && jw_htable_get_node(config, key))
    {
        char *dstr = jw_htable_get(config, key);
        char *pEnd;
        errno = 0;

        ret = strtod(dstr, &pEnd);

        if (errno || ('\0' != *pEnd))
        {
            jw_log(JW_LOG_WARN,
                   "cannot convert string '%s' to double: %s",
                   dstr, errno ? strerror(errno) : "invalid string");
            JABBERWERX_ERROR(err, JW_ERR_INVALID_ARG);
            return false;
        }
    }

    if (val)
    {
        *val = ret;
    }
    
    return true;
}
