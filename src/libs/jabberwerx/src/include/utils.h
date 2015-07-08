/**
 * \file
 * \brief
 * General internal utility functions.
 *
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

#ifndef JABBERWERX_UTILS_H
#define JABBERWERX_UTILS_H

#include <jabberwerx/util/htable.h>

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * converts a seconds.milliseconds double to time_t milliseconds.
 */
uint32_t jw_utils_dtoms(double dbl);

/**
 * retrieves a stringified floating point value from a htable and converts it to
 * a double value.
 */
bool jw_utils_config_get_double(jw_htable *config,
                                const char     *key,
                                double          default_val,
                                double         *val,
                                jw_err         *err);

#ifdef __cplusplus
}
#endif

#endif // JABBERWERX_UTILS_H
