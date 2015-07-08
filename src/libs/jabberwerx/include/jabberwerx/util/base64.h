/**
 * \file
 * \brief
 * Functions for encoding to and decoding from Base 64
 *
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

#ifndef JABBERWERX_UTIL_BASE64_H
#define JABBERWERX_UTIL_BASE64_H

#include <sys/types.h>
#include "../basics.h"


#ifdef __cplusplus
extern "C"
{
#endif

/**
 * Encode a byte array into a base64 byte array (without whitespace). The
 * result buffer is null-terminated. If orig_len is 0,
 * result is an empty string.
 *
 * \b NOTE: This function will allocate the memory needed to store the
 * encoded data. Result MUST be released using jw_data_free.
 *
 * This function can generate the following errors (set when returning false):
 * \li \c JW_ERR_NO_MEMORY If result buffer could not be allocated.
 *
 * \invariant result != NULL
 * \invariant orig != NULL
 * \param[in] orig The array containing the bytes to encode.
 * \param[in] orig_len The number of bytes to encode from orig
 * \param[out] result The output byte array where the encoded data is stored.
 * \param[out] result_len If non-NULL, the size of the new allocated result
 *              byte array.
 * \param[out] err The error information (provide NULL to ignore)
 * \retval bool true if encoding was successful, false otherwise.
 */
JABBERWERX_API bool jw_base64_encode(const uint8_t *orig,
                                     size_t         orig_len,
                                     char         **result,
                                     size_t        *result_len,
                                     jw_err        *err);

/**
 * Decode base64 encoded byte array (without whitespace) into nonencoded
 * binary stream. If  orig_len is -1, this function uses strlen(orig) to
 * determine the size. If orig_len is 0 then result is an "empty string"
 * (*result && **result = 0).
 *
 * \b NOTE: This function will allocate the memory needed to store the
 * decoded data. Result MUST be released using jw_data_free.
 *
 * This function can generate the following errors (set when returning false):
 * \li \c JW_ERR_INVALID_ARG If orig contains bytes that are not
 *     Base 64 encoding, or if orig_len < -1
 * \li \c JW_ERR_NO_MEMORY If result buffer could not be allocated.
 *
 * \invariant result != NULL
 * \invariant orig != NULL
 * \invariant result_len != NULL
 * \param[in] orig The array containing the base 64 data to decode.
 * \param[in] orig_len The number of bytes to decode from orig or
 *                     -1 to calculate.
 * \param[out] result The output byte array where the decoded data is stored.
 * \param[out] result_len The size of the new allocated result byte array.
 * \param[out] err The error information (provide NULL to ignore)
 * \retval bool true if decoding was successful, or false otherwise
 */
JABBERWERX_API bool jw_base64_decode(const char *orig,
                                     ssize_t     orig_len,
                                     uint8_t   **result,
                                     size_t     *result_len,
                                     jw_err     *err);

#ifdef __cplusplus
}
#endif

#endif /* JABBERWERX_UTIL_BASE64_H */
