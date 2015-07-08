/**
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

#ifndef STREAM_TEST_H
#define STREAM_TEST_H

/**
 * \file
 *
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2011 Cisco Systems, Inc.  All Rights Reserved.
 */

#include <jabberwerx/stream.h>


typedef bool (*_test_create_stream_cb)(
                jw_workq *workq, jw_stream **stream, jw_err *err);
typedef bool (*_test_before_bind_cb)(
                jw_stream *stream, jw_htable *config, void *arg, bool *failed);
typedef void (*_test_before_cleanup_cb)(void *arg);
typedef bool (*_test_after_presence_cb)(
                jw_stream *stream, void *arg, bool *failed);

struct _test_stream_hooks
{
    _test_create_stream_cb  create_stream_cb;
    _test_before_bind_cb    before_bind_cb;
    void                   *before_bind_cb_arg;
    _test_before_cleanup_cb before_cleanup_cb;
    void                   *before_cleanup_cb_arg;
    _test_after_presence_cb after_presence_cb;
    void                   *after_presence_cb_arg;
};

void _test_stream_hooks_init(_test_create_stream_cb     create_stream_cb,
                             struct _test_stream_hooks *hooks);
bool _test_stream_basic(struct _test_stream_hooks *hooks,
                        jw_err                    *err);
bool _test_stream_no_config(struct _test_stream_hooks *hooks,
                            jw_err                    *err);
bool _test_stream_destroy_from_close(struct _test_stream_hooks *hooks,
                                     jw_err                    *err);
bool _test_stream_keepalive(struct _test_stream_hooks *hooks,
                            jw_err                    *err);
bool _test_stream_error_elem(struct _test_stream_hooks *hooks,
                             jw_err                    *err);

void _test_remove_expat_malloc_monitoring();
void _test_restore_expat_malloc_monitoring();

#endif  // STREAM_TEST_H
