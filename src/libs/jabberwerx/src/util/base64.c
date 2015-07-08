/**
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

#include "jabberwerx/util/base64.h"
#include "jabberwerx/util/mem.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#define B64_BYTE1(ptr) (((*ptr) & 0xfc)>>2)
#define B64_BYTE2(ptr) ((((*ptr) & 0x03)<<4) | ((*(ptr+1)&0xf0)>>4))
#define B64_BYTE3(ptr) (((*(ptr+1) & 0x0f)<< 2) | ((*(ptr+2)&0xc0)>>6))
#define B64_BYTE4(ptr) (*(ptr+2) & 0x3f)


static const char* G_B64_ENCODE_TAB =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static const uint8_t G_B64_DECODE_TAB[] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0x3e, 0xff, 0xff, 0xff, 0x3f,
    0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
    0x3c, 0x3d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
    0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
    0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
    0x17, 0x18, 0x19, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
    0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
    0x31, 0x32, 0x33, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

JABBERWERX_API bool jw_base64_encode(const uint8_t *orig,
                                     size_t         orig_len,
                                     char         **result,
                                     size_t        *result_len,
                                     jw_err        *err)
{
    const uint8_t *lim;
    char       *res;
    char       *base;
    size_t      rlen;

    assert(orig != NULL);
    assert(result != NULL);

    /*return empty string on 0 length input */
    if (!orig_len)
    {
        char * retVal = (char *)jw_data_malloc(1);
        if (!retVal)
        {
            JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
            return false;
        }
        *result = retVal;
        **result = 0;
        if (NULL != result_len)
        {
            *result_len = 0;
        }
        return true;
    }

    rlen = (((orig_len + 2) / 3) << 2);
    base = res = (char *)jw_data_malloc(rlen+1);
    if (!res)
    {
        JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
        return false;
    }

    lim = orig + orig_len;
    for ( ; orig < (lim-2) ; orig += 3, orig_len -= 3)
    {
        *res++ = G_B64_ENCODE_TAB[B64_BYTE1(orig)];
        *res++ = G_B64_ENCODE_TAB[B64_BYTE2(orig)];
        *res++ = G_B64_ENCODE_TAB[B64_BYTE3(orig)];
        *res++ = G_B64_ENCODE_TAB[B64_BYTE4(orig)];
    }

    if( orig < lim)
    {
        if ( orig == (lim-1) )
        {
            *res++ = G_B64_ENCODE_TAB[B64_BYTE1(orig)];
            *res++ = G_B64_ENCODE_TAB[(*(orig) & 0x03)<<4];
            *res++ = '=';
            *res++ = '=';
        }
        else
        {
            *res++ = G_B64_ENCODE_TAB[B64_BYTE1(orig)];
            *res++ = G_B64_ENCODE_TAB[B64_BYTE2(orig)];
            *res++ = G_B64_ENCODE_TAB[((*(orig+1) & 0x0f)<< 2)];
            *res++ = '=';
        }

    }

    base[rlen] = '\0';

    *result = base;
    if (NULL != result_len)
    {
        *result_len = rlen;
    }
    return true;
}

static inline size_t _jw_base64_decode_size(const char *orig, size_t orig_len)
{

    size_t result = (orig_len>>2)*3;
    const char *ptr = orig+(orig_len-1);

    while(*ptr-- == '=')
    {
        --result;
    }
    return result;
}

JABBERWERX_API bool jw_base64_decode(const char *orig,
                                     ssize_t     orig_len,
                                     uint8_t   **result,
                                     size_t     *result_len,
                                     jw_err     *err)
{
    size_t rlen;
    uint8_t *res, *base;
    int bytes = 0;
    int shift = 18;
    int final_shift = 16;
    const char *lim;

    assert(orig != NULL);
    assert(result != NULL);
    assert(result_len != NULL);

    if (orig_len < -1)
    {
        JABBERWERX_ERROR(err, JW_ERR_INVALID_ARG);
        return false;
    }
    if (orig_len == -1)
    {
        orig_len = strlen(orig);
    }
    /*return empty string on 0 length input */
    if (!orig_len)
    {
        uint8_t * retVal = (uint8_t *)jw_data_malloc(1);
        if (!retVal)
        {
            JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
            return false;
        }
        *result = retVal;
        **result = *result_len = 0;
        return true;
    }

    // The input must be a multiple of 4
    if ( (orig_len & 0x03) != 0 )
    {
        JABBERWERX_ERROR(err, JW_ERR_INVALID_ARG);
        return false;
    }

    rlen = _jw_base64_decode_size(orig, orig_len);
    base = res = (uint8_t *)jw_data_malloc(rlen);
    if (!res)
    {
        JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
        return false;
    }

    lim = orig + orig_len;
    for ( ; orig < lim && *orig != '='; ++orig, shift -= 6 )
    {
        int val = G_B64_DECODE_TAB[(int)(*orig)];
        if ( val == 0xff )
        {
            JABBERWERX_ERROR(err, JW_ERR_INVALID_ARG);
            jw_data_free(base);
            return false;
        }

        bytes |= (val << shift);
        if ( !shift )
        {
            *res++ = (bytes >> 16) & 0xff;
            *res++ = (bytes >> 8) & 0xff;
            *res++ = bytes & 0xff;
            shift = 24;
            bytes = 0;
        }
    }

    if ( shift != 18 )
    {
        while ( shift != 12 )
        {
            *res++ = (bytes >> final_shift) & 0xff;
            final_shift -= 8;
            shift += 6;
        }
    }

    *result = base;
    *result_len = rlen;
    return true;
}
