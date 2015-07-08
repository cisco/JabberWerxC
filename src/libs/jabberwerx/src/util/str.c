/**
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

#include "jabberwerx/util/str.h"

#include <stdlib.h>
#include <string.h>

/****************************************************************************
 * EXTERNAL functions
 */

JABBERWERX_API int jw_atoi(const char *a, int def)
{
    if (a == NULL)
    {
        return def;
    }
    return atoi(a);
}

JABBERWERX_API size_t jw_strlen(const char *a)
{
    if (a == NULL)
    {
        return 0;
    }
    return strlen(a);
}

JABBERWERX_API size_t jw_strnlen(const char *a, size_t len)
{
    size_t i;
    if (a == NULL)
    {
        return 0;
    }
    for (i=0; i < len && a[i]; i++) {
	/* no-op */
    }
    return i;
}

JABBERWERX_API int jw_strcmp(const char *a, const char *b)
{
    if (a == b)
    {
        return 0;
    }
    if (a == NULL)
    {
        return -1;
    }
    if (b == NULL)
    {
        return 1;
    }
    return strcmp(a, b);
}

JABBERWERX_API int jw_strcasecmp(const char *a, const char *b)
{
    if (a == b)
    {
        return 0;
    }
    if (a == NULL)
    {
        return -1;
    }
    if (b == NULL)
    {
        return 1;
    }
    return strcasecmp(a, b);
}

JABBERWERX_API int jw_strncmp(const char *a, const char *b, size_t n)
{
    if (a == b)
    {
        return 0;
    }
    if (a == NULL)
    {
        return -1;
    }
    if (b == NULL)
    {
        return 1;
    }
    return strncmp(a, b, n);
}

JABBERWERX_API int jw_strncasecmp(const char *a, const char *b, size_t n)
{
    if (a == b)
    {
        return 0;
    }
    if (a == NULL)
    {
        return -1;
    }
    if (b == NULL)
    {
        return 1;
    }
    return strncasecmp(a, b, n);
}
