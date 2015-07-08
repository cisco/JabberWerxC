/**
 * \file
 * simpleclient_utils.h
 *
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2011 Cisco Systems, Inc.  All Rights Reserved.
 */

#ifndef SIMPLECLIENT_UTILS_H
#define SIMPLECLIENT_UTILS_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <jabberwerx/dom.h>
#include <jabberwerx/client.h>

void printElement(jw_dom_node *element);
void printElements(jw_dom_node **elements);
void dumpEventData(jw_dom_node *node, char *message);

const char *getStatusString(jw_client_statustype type);

#ifdef __cplusplus
}
#endif

#endif  /* SIMPLECLIENT_UTILS_H */
