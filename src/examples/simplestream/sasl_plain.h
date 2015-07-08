/**
 * \file
 * sasl_plain.h
 *
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2011 Cisco Systems, Inc.  All Rights Reserved.
 */

#ifndef SIMPLECLIENT_SASL_PLAIN_H
#define SIMPLECLIENT_SASL_PLAIN_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <jabberwerx/stream.h>
#include <jabberwerx/dom.h>

bool doSaslPlain(jw_stream *stream, jw_dom_node *node, jw_htable *config);

#ifdef __cplusplus
}
#endif

#endif  /* SIMPLECLIENT_SASL_PLAIN_H */
