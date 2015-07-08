/**
 * \file
 * \brief
 * Internal functions that abstract unicode-related functionality.
 * 
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

#ifndef JABBERWERX_UNICODE_INT_H
#define	JABBERWERX_UNICODE_INT_H

#include <stddef.h>
#include <inttypes.h>

#ifdef	__cplusplus
extern "C" {
#endif

/**
 * Transforms a nameprepped domain label to an ACE (ASCII-compatible encoding)
 * label, which includes the "xn--" prefix if a transformation took place.
 * 
 * @return the length of the ACE label, not including the terminating NULL.  If
 *         this number is >= aceLabelBufLen, then the given buffer was not large
 *         enough to hold the returned string.  If the buffer is too small, the
 *         contents of the buffer after the function call are undefined.  If
 *         namepreppedLabel cannot be converted to an ACE label, -1 is returned.
 */
int32_t unicode_make_ace_label_int(const uint8_t * namepreppedLabel,
                                   size_t          namepreppedLabelLen,
                                   uint8_t       * aceLabelBuf,
                                   size_t          aceLabelBufSize);

/**
 * Applies the nodeprep stringprep profile to a given string.  Returns the
 * length of the string written to outBuf, or a negative number if outBuf is not
 * big enough or if the stringprep profile cannot be successfully applied to
 * str.
 */
int32_t unicode_nodeprep_int(const uint8_t * str, size_t strLen,
                             uint8_t * outBuf, size_t outBufSize);

/**
 * Applies the nameprep stringprep profile to a given string.  Returns the
 * length of the string written to outBuf, or a negative number if outBuf is not
 * big enough or if the stringprep profile cannot be successfully applied to
 * str.
 */
int32_t unicode_nameprep_int(const uint8_t * str, size_t strLen,
                             uint8_t * outBuf, size_t outBufSize);

/**
 * Applies the resourceprep stringprep profile to a given string.  Returns the
 * length of the string written to outBuf, or a negative number if outBuf is not
 * big enough or if the stringprep profile cannot be successfully applied to
 * str.
 */
int32_t unicode_resourceprep_int(const uint8_t * str, size_t strLen,
                                 uint8_t * outBuf, size_t outBufSize);

#ifdef	__cplusplus
}
#endif

#endif	/* JABBERWERX_UNICODE_INT_H */
