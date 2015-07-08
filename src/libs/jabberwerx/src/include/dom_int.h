/**
 * \file
 * \brief
 * Internal functions that implement select funtionalty specified in dom.h,
 * made available separately for performance reasons.
 *
 * The functions prototyped in this file do not validate the UTF-8 form of their
 * text parameters, and therefore provide a high-performance interface to the
 * dom funtionality for clients within the |JWC| library that have already
 * validated their input.
 *
 * Please see dom.h for the documented public API.
 *
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

#ifndef JABBERWERX_DOM_INT_H
#define	JABBERWERX_DOM_INT_H

#include <jabberwerx/dom.h>

#ifdef	__cplusplus
extern "C"
{
#endif

/**
 * Non-validating version of jw_dom_element_create.
 */
bool jw_dom_element_create_int(jw_dom_ctx *ctx,
                               const char *ename,
                               jw_dom_node **elem,
                               jw_err *err);

/**
 * Non-validating version of jw_dom_text_create.
 */
bool jw_dom_text_create_int(jw_dom_ctx *ctx,
                            const char *value,
                            jw_dom_node **text,
                            jw_err *err);

/**
 * Non-validating version of jw_dom_put_namespace.
 */
bool jw_dom_put_namespace_int(jw_dom_node *elem,
                              const char *prefix,
                              const char *uri,
                              jw_err *err);

/**
 * Non-validating version of jw_dom_set_attribute.
 */
bool jw_dom_set_attribute_int(jw_dom_node *elem,
                              const char *ename,
                              const char *value,
                              jw_err *err);

#ifdef	__cplusplus
}
#endif

#endif	/* JABBERWERX_DOM_INT_H */
