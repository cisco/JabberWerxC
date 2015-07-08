/**
 * \file
 * simpleclient_utils.c
 *
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2011 Cisco Systems, Inc.  All Rights Reserved.
 */

#include "simpleclient_utils.h"

#include <jabberwerx/util/serializer.h>
#include <jabberwerx/util/log.h>

#include <stdio.h>

void printElement(jw_dom_node *element)
{
    char *str;
    size_t len;

    jw_serialize_xml(element, &str, &len, NULL);
    jw_log(JW_LOG_INFO, "[%s]", str);
    jw_data_free(str);
}

void printElements(jw_dom_node **elements)
{
    int index;

    for (index = 0; elements[index] != NULL; index++)
    {
        printElement(elements[index]);
    }

}

void dumpEventData(jw_dom_node *node, char *message)
{
    if (message)
    {
        printf("%s\n", message);
    }
    
    if (node)
    {
        printElement(node);
    }
}

const char *getStatusString(jw_client_statustype type)
{
    switch(type)
    {
        case JW_CLIENT_DISCONNECTED:
            return "disconnected";
        case JW_CLIENT_CONNECTING:
            return "connecting";
        case JW_CLIENT_CONNECTED:
            return "connected";
        case JW_CLIENT_DISCONNECTING:
            return "disconnecting";
        default:
            return "should never be here!";
    }
}
