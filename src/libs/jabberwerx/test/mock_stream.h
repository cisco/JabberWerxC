/**
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

#ifndef JABBERWERX_TEST_MOCK_STREAM_H
#define JABBERWERX_TEST_MOCK_STREAM_H

#include <jabberwerx/stream.h>

/**
 * Create a mock stream that does nothing.
 *
 * \invariant workq != NULL
 * \invariant stream != NULL
 * \param[in] workq the workq to use for triggering events asynchronously
 * \param[out] stream The newly created stream.
 * \param[out] err The error information (provide NULL to ignore)
 * \retval bool true if the stream was created successfully.
 */
JABBERWERX_API bool jw_stream_mock_create(jw_workq   *workq,
                                          jw_stream **stream,
                                          jw_err    *err);

/**
 * Pretend that the given element has been received from a "server".
 * 
 * \invariant stream != NULL
 * \invariant stanza != NULL
 * \param[out] err The error information (provide NULL to ignore)
 * \retval bool true if the stanza was sent successfully.
 */
JABBERWERX_API bool jw_stream_mock_receive(jw_stream   *stream,
                                           jw_dom_node *stanza,
                                           jw_err      *err);

#endif /* JABBERWERX_TEST_MOCK_STREAM_H */
