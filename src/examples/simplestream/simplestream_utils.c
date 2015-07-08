/**
 * \file
 * simplestream_utils.c
 *
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2011 Cisco Systems, Inc.  All Rights Reserved.
 */

#include "simplestream_utils.h"

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
