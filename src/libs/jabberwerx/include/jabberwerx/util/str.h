/**
 * \file
 * \brief
 * Standard string functions that handle NULL inputs
 *
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

#ifndef JABBERWERX_UTIL_STR_H
#define JABBERWERX_UTIL_STR_H

#include "../basics.h"


#ifdef __cplusplus
extern "C"
{
#endif

/**
 * Converts the given string into an integer. This function behaves as atoi,
 * except that a may be NULL.
 *
 * \param a The string to convert to an integer
 * \param def The default value to return
 * \retval int The integer representation of a, or def if NULL
 */
JABBERWERX_API int jw_atoi(const char *a, int def);

/**
 * Determines the length of the given string. This function
 * behaves as strlen, except that a may be NULL.
 *
 * \param a The string to determine the length of
 * \retval size_t The length of a, or 0 if a is NULL
 */
JABBERWERX_API size_t jw_strlen(const char *a);

/**
 * Determines the length of the given string. This function
 * behaves as strnlen, except that a may be NULL.
 *
 * \param a The string to determine the length of
 * \param len The maximum length to consider
 * \retval size_t The length of a, or 0 if a is NULL
 */
JABBERWERX_API size_t jw_strnlen(const char *a, size_t len);

/**
 * Compares two NULL-terminated strings (case-sensitive), allowing for either
 * to be NULL. This function behaves as strcmp, with the difference that a
 * and/or b may be NULL.
 *
 * \param a The first string to compare
 * \param b The second string to compare
 * \retval int less than 0 if a is before b;
 *             greater than 0 if a is after b;
 *             0 if a and be are equal
 */
JABBERWERX_API int jw_strcmp(const char *a, const char *b);

/**
 * Compares two NULL-terminated strings (case-insensitive), allowing for either
 * to be NULL. This function behaves as strcasecmp, with the difference that a
 * and/or b may be NULL.
 *
 * \param a The first string to compare
 * \param b The second string to compare
 * \retval int less than 0 if a is before b;
 *             greater than 0 if a is after b;
 *             0 if a and be are equal
 */
JABBERWERX_API int jw_strcasecmp(const char *a, const char *b);

/**
 * Compares part of two NULL-terminated strings, allowing for either to be
 * NULL. This function behaves as strncmp, with the difference that a and/or
 * b may be NULL.
 *
 * \param a The first string to compare
 * \param b The second string to compare
 * \param n The number of bytes to compare
 * \retval int less than 0 if a is before b;
 *             greater than 0 if a is after b;
 *             0 if a and be are equal
 */
JABBERWERX_API int jw_strncmp(const char *a, const char *b, size_t n);

/**
 * Compares two NULL-terminated strings (case-insensitive), allowing for either
 * to be NULL. This function behaves as strncasecmp, with the difference that a
 * and/or b may be NULL.
 *
 * \param a The first string to compare
 * \param b The second string to compare
 * \param n The number of bytes to compare
 * \retval int less than 0 if a is before b;
 *             greater than 0 if a is after b;
 *             0 if a and be are equal
 */
JABBERWERX_API int jw_strncasecmp(const char *a, const char *b, size_t n);

#ifdef __cplusplus
}
#endif

#endif /* JABBERWERX_UTIL_STR_H */
