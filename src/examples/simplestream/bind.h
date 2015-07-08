/**
 * \file
 * bind.h
 *
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2011 Cisco Systems, Inc.  All Rights Reserved.
 */

#ifndef SIMPLECLIENT_BIND_H
#define SIMPLECLIENT_BIND_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <jabberwerx/stream.h>
#include <jabberwerx/dom.h>

bool doBind(jw_stream *stream, jw_dom_node *node);

#ifdef __cplusplus
}
#endif

#endif  /* SIMPLECLIENT_BIND_H */
