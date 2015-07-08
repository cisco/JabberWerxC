/**
 * \file
 * simplestream_utils.h
 *
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2011 Cisco Systems, Inc.  All Rights Reserved.
 */

#ifndef SIMPLESTREAM_UTILS_H
#define SIMPLESTREAM_UTILS_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <jabberwerx/dom.h>

void printElement(jw_dom_node *element);
void printElements(jw_dom_node **elements);

#ifdef __cplusplus
}
#endif

#endif  /* SIMPLESTREAM_UTILS_H */
