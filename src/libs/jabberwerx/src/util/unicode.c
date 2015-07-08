/**
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

#ifdef JABBERWERX_STRINGPREP_ASCII
# include <ctype.h>
#else
# include <string.h>
# include <stdlib.h>
# include <stringprep.h>
# include <idna.h>

#include "jabberwerx/util/mem.h"
#endif

#include "jabberwerx/basics.h"
#include "../include/unicode_int.h"


#ifndef JABBERWERX_STRINGPREP_ASCII

static int _stringprep(const uint8_t * str, size_t strLen,
                       uint8_t * outBuf, size_t outBufSize,
                       const Stringprep_profile * profile)
{
    // use outBuf as the in/out buffer if it is big enough.  otherwise, use
    // a temporary buffer
    char * spBuf;
    size_t spBufSize;
    if (outBufSize > strLen)
    {
        spBufSize = outBufSize;
        spBuf = (char *)outBuf;
    }
    else
    {
        spBufSize = strLen + 1;
        spBuf = jw_data_malloc(spBufSize);
        if (NULL == spBuf)
        {
            // TODO: log error
            return -1;
        }
    }

    memcpy(spBuf, str, strLen);
    spBuf[strLen]='\0';

    if (STRINGPREP_OK != stringprep(spBuf, spBufSize, 0, profile))
    {
        if ((char *)outBuf != spBuf)
        {
            jw_data_free(spBuf);
        }
        // TODO: log error
        return -1;
    }

    size_t outLen = strlen(spBuf);

    // if we allocated a temporary buffer, copy back to outbuf and clean up
    if ((char *)outBuf != spBuf)
    {
        if (outBufSize <= outLen)
        {
            jw_data_free(spBuf);
            // TODO: log error
            return -1;
        }

        memcpy(outBuf, spBuf, outLen+1);
        jw_data_free(spBuf);
    }

    return outLen;
}
#endif


///////////////////////////////////////////////////////////////////////////////
//
// public API
//

int32_t unicode_make_ace_label_int(const uint8_t * namepreppedLabel,
                                   size_t          namepreppedLabelLen,
                                   uint8_t       * aceLabelBuf,
                                   size_t          aceLabelBufSize)
{
#ifdef JABBERWERX_STRINGPREP_ASCII
    UNUSED_PARAM(namepreppedLabel);
    UNUSED_PARAM(namepreppedLabelLen);
    UNUSED_PARAM(aceLabelBuf);
    UNUSED_PARAM(aceLabelBufSize);

    return -1;
#else
    // this will all be much more efficient once we are using libicu
#define JWUNICODE_IN_BUF_SIZE 64
    char inBuf[JWUNICODE_IN_BUF_SIZE];
    char * outBuf;

    if (JWUNICODE_IN_BUF_SIZE <= namepreppedLabelLen)
    {
        // TODO: log error
        return -1;
    }

    memcpy(inBuf, namepreppedLabel, namepreppedLabelLen);
    inBuf[namepreppedLabelLen] = '\0';

    if (IDNA_SUCCESS != idna_to_ascii_8z(inBuf, &outBuf, IDNA_ALLOW_UNASSIGNED))
    {
        // TODO: log error
        return -1;
    }

    size_t outLen = strlen(outBuf);

    // if there is sufficient space in the output buffer, copy the data in
    if (aceLabelBufSize > outLen)
    {
        memcpy(aceLabelBuf, outBuf, outLen+1);
    }

    // outBuf is allocated internally to libidn with malloc; use free instead of
    // jw_data_free
    free(outBuf);
    return outLen;
#undef JWUNICODE_IN_BUF_SIZE
#endif
}

// TODO: it may be beneficial to add a strinprep cache.  further
// TODO:   research is required
int32_t unicode_nodeprep_int(const uint8_t * str, size_t strLen,
                             uint8_t * outBuf, size_t outBufSize)
{
#ifdef JABBERWERX_STRINGPREP_ASCII
    return unicode_nameprep_int(str, strLen, outBuf, outBufSize);
#else
    return _stringprep(str, strLen, outBuf, outBufSize,
                       stringprep_xmpp_nodeprep);
#endif
}

int32_t unicode_nameprep_int(const uint8_t * str, size_t strLen,
                             uint8_t * outBuf, size_t outBufSize)
{
#ifdef JABBERWERX_STRINGPREP_ASCII
    // success if all input is ascii; lcase input to output
    size_t idx;
    for (idx = 0; strLen > idx; ++idx)
    {
        if (idx >= outBufSize)
        {
            // TODO: log error
            return -1;
        }

        if (0 != (0x80 & str[idx]))
        {
            // TODO: log error
            return -1;
        }

        outBuf[idx] = tolower(str[idx]);
    }

    if (idx >= outBufSize)
    {
        // TODO: log error
        return -1;
    }
    outBuf[idx] = '\0';

    return idx;
#else
    return _stringprep(str, strLen, outBuf, outBufSize, stringprep_nameprep);
#endif
}

int32_t unicode_resourceprep_int(const uint8_t * str, size_t strLen,
                                 uint8_t * outBuf, size_t outBufSize)
{
#ifdef JABBERWERX_STRINGPREP_ASCII
    // success if all input is ascii; copy input to output
    size_t idx;
    for (idx = 0; strLen > idx; ++idx)
    {
        if (idx >= outBufSize)
        {
            // TODO: log error
            return -1;
        }

        if (0 != (0x80 & str[idx]))
        {
            // TODO: log error
            return -1;
        }

        outBuf[idx] = str[idx];
    }

    if (idx >= outBufSize)
    {
        // TODO: log error
        return -1;
    }
    outBuf[idx] = '\0';

    return idx;
#else
    return _stringprep(str, strLen, outBuf, outBufSize,
                       stringprep_xmpp_resourceprep);
#endif
}
