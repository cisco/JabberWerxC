/**
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

// for asprintf
#define _GNU_SOURCE

#include "test_utils.h"
#include "stanza_defines.h"
#include "event2/bufferevent_struct.h"
#include <jabberwerx/client.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>


static uint32_t _mallocCnt = 0;
static void *_counting_malloc(size_t size)
{
    ++_mallocCnt;
    return malloc(size);
}
uint32_t _test_get_malloc_count()
{
    return _mallocCnt;
}

static void *_counting_realloc(void *ptr, size_t size)
{
    if (NULL == ptr)
    {
        return _counting_malloc(size);
    }
    return realloc(ptr, size);
}

static int _freeCnt = 0;
static void _counting_free(void *ptr)
{
    if (NULL == ptr)
    {
        return;
    }
    ++_freeCnt;
    free(ptr);
}
uint32_t _test_get_free_count()
{
    return _freeCnt;
}

void _test_init_counting_memory_funcs()
{
    _mallocCnt = 0;
    _freeCnt = 0;
    jw_data_set_memory_funcs(
            _counting_malloc, _counting_realloc, _counting_free);
}

void _test_uninit_counting_memory_funcs()
{
    jw_data_set_memory_funcs(NULL, NULL, NULL);
}

static bool _timedOut = false;
static void _failsafe_cb(evutil_socket_t fd, short what, void *arg)
{
    UNUSED_PARAM(fd);
    UNUSED_PARAM(what);

    jw_log(JW_LOG_ERROR, "test timed out");

    assert(0 != fd);

    _timedOut = true;

    struct event_base *evbase = arg;
    event_base_loopbreak(evbase);
}
bool _test_get_timed_out()
{
    return _timedOut;
}

static void _asprintf_cleanfunc(bool replace, bool destroy_key,
                                void *key,    void *data)
{
    UNUSED_PARAM(replace);
    UNUSED_PARAM(destroy_key);
    UNUSED_PARAM(key);

    free(data);
}

bool _test_config_set_echosrv_port(
        jw_htable *config, jw_test_echosrv echosrv)
{
    if (echosrv)
    {
        char    *portStr = NULL;
        uint16_t port    = _jw_test_echosrv_get_port(echosrv);

        if (0 >= asprintf(&portStr, "%u", port))
        {
            return false;
        }

        if (!jw_htable_put(config, JW_STREAM_CONFIG_PORT, portStr,
                           _asprintf_cleanfunc, NULL))
        {
            _asprintf_cleanfunc(false, false, NULL, portStr);
            return false;
        }
    }

    return true;
}

bool _test_init_config(
        jw_htable *config, struct event_base *evbase, jw_test_echosrv echosrv)
{
    jw_htable_clear(config);

    _test_config_set_echosrv_port(config, echosrv);

    return
        jw_htable_put(config, JW_STREAM_CONFIG_NAMESPACE, XMPP_CLIENT_URI, NULL, NULL) &&
        jw_htable_put(config, JW_STREAM_CONFIG_DOMAIN, "-internal", NULL, NULL) &&
        jw_htable_put(config, JW_CLIENT_CONFIG_USERJID, "testuser@localhost", NULL, NULL) &&
        jw_htable_put(config, JW_CLIENT_CONFIG_USERPW, "pass", NULL, NULL) &&
        jw_htable_put(config, JW_STREAM_CONFIG_HOST, "127.0.0.1", NULL, NULL) &&
        jw_htable_put(config, JW_STREAM_CONFIG_URI, "http://127.0.0.1/bosh", NULL, NULL) &&
        jw_htable_put(config, JW_STREAM_CONFIG_SELECTOR, evbase, NULL, NULL) &&
        jw_htable_put(config, JW_CLIENT_CONFIG_STREAM_TYPE, "socket", NULL, NULL) &&
        jw_htable_put(config, JW_CLIENT_CONFIG_RECONNECT_BASE_COUNTDOWN, "0", NULL, NULL);
}

bool _test_init_failsafe(struct event_base *evbase,
                         struct event     **failsafeEvent,
                         uint32_t           numSeconds)
{
    _timedOut = false;
    *failsafeEvent = evtimer_new(evbase, _failsafe_cb, evbase);
    struct timeval timeout = { numSeconds, 0 };
    return *failsafeEvent && 0 == evtimer_add(*failsafeEvent, &timeout);
}

bool _test_init(struct event_base **evbase, struct event **failsafeEvent,
                jw_htable **config, jw_workq **workq, jw_test_echosrv *echosrv)
{
    *evbase = event_base_new();
    if (!*evbase)
    {
        return false;
    }

    // a failsafe timer to ensure that we don't get deadlocked waiting for
    // events that won't ever happen (because of a bug, presumably)
    // this is set to five seconds since is seems that shorter durations will
    // cause tests run under valgrind to erroneously time out.
    if (failsafeEvent)
    {
        if (!_test_init_failsafe(*evbase, failsafeEvent, 5))
        {
            return false;
        }
    }

    if (config && !jw_htable_create(11, jw_str_hashcode, jw_str_compare,
                                    config, NULL)) { return false; }
    if (config && !_test_init_config(*config, *evbase, NULL)) { return false; }
    if (config && workq && !jw_workq_create(*config, workq, NULL)) { return false; }
    if (workq && echosrv && !_jw_test_echosrv_create(*workq, echosrv, NULL)) { return false; }
    jw_test_echosrv esrv = echosrv ? *echosrv : NULL;
    if (config && !_test_config_set_echosrv_port(*config, esrv)) { return false; }

    return true;
}

void _test_cleanup(struct event_base *evbase, struct event *failsafeEvent,
                   jw_htable *config, jw_workq *workq, jw_test_echosrv echosrv)
{
    if (echosrv)       { _jw_test_echosrv_destroy(echosrv); }
    if (workq)         { jw_workq_destroy(workq);     }
    if (config)        { jw_htable_destroy(config);   }
    if (failsafeEvent) { event_free(failsafeEvent);   }
    if (evbase)        { event_base_free(evbase);     }
}
