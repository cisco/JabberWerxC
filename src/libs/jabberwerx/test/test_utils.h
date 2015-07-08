/**
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

#ifndef TEST_UTILS_H
#define TEST_UTILS_H

#include <jabberwerx/util/log.h>
#include <jabberwerx/util/workq.h>
#include <event2/event.h>
#include "echosrv.h"


/**
 * Out of memory test data
 */
typedef struct _oom_test_data_int
{
    int  jwcAllocCount;  //# of non-3rdparty allocation calls
    //The most jwc allocs allowed during a failure test, -1 disables limiting
    int  jwcAllocLimit;
    //the number of fail tests to be attempted. see OOM_RECORD_ALLOCS
    int  failureAttempts;
    int numMallocCalls, numReallocCalls, numFreeCalls;
} oom_test_data;

/**
 * Enable or disable oom testing. OOM testing swaps jw_data*
 * allocation functions with ones that count and limit calls.
 *
 * \param enabled True to swap in oom testing allocation functions,
 *        false for default
 */
void oom_set_enabled(bool enabled);

/**
 * Get the oom_test_data associated with the current tests. User does not
 * own the structure reference returned and should not free it.
 *
 * \retval oom_test_data the structure containing current oom testing data.
 *         will never return NULL.
 */
oom_test_data *oom_get_data();

/**
 * Several macros are defined to simplify out-of-memory testing.
 *
 * OOM_RECORD_ALLOCS takes an expression to test. Custom allocation functions
 * are swapped in and then the expression is evaluated (and the result tested
 * to ensure the expression returned "true"). The number of allocations required
 * for a good evaluation is then stored in the failureAttempts variable and
 * used in later macros.
 *
 * Tests expr result using fct_req
 */
#define OOM_RECORD_ALLOCS(expr) \
{ \
    bool _oom_result; \
    oom_set_enabled(true); \
    _oom_result = (expr); \
    oom_get_data()->failureAttempts = oom_get_data()->jwcAllocCount; \
    oom_set_enabled(false); \
    fct_req(_oom_result); \
    jw_log(JW_LOG_INFO, "testing %u alloc failures for expression: '%s'", \
           oom_get_data()->failureAttempts, #expr); \
}

/**
 * Two macros work together to iterate over the failureAttempts.
 * OOM_TEST_INIT should be followed by cleanup and initialization logic invoked
 * with every fail test attempt. These functions are typically paired with
 * OOM_RECORD_ALLOCS so the cleanup/init order works correctly.
 *
 * A typical OOM test using OOM_TEST_INIT, OOM_TEST might look like:
 *
 *       jw_jid_ctx ctx;
 *       jw_jid jid;
 *       jw_err err;
 *
 *       fct_req(jw_jid_context_create(0, &ctx, NULL));
 *       OOM_RECORD_ALLOCS(jw_jid_create(ctx, "foo@bar/baz", &jid, &err))
 *       oom_get_data()->failureAttempts = 1;
 *       OOM_TEST_INIT()
 *           jw_jid_context_destroy(ctx);
 *           fct_req(jw_jid_context_create(0, &ctx, NULL));
 *       OOM_TEST(&err, jw_jid_create(ctx, "foo@bar/baz", &jid, &err))
 *      jw_jid_context_destroy(ctx);
 */
#define OOM_TEST_INIT() \
{ \
    oom_test_data *oom_data = oom_get_data(); \
    for (int _oom_idx = 0; _oom_idx < oom_data->failureAttempts; ++_oom_idx) \
    { \
        jw_log(JW_LOG_INFO, "starting OOM iteration %d of %d", \
               _oom_idx + 1, oom_data->failureAttempts); \
        oom_set_enabled(false); \

#define OOM_TEST_CONDITIONAL_CHECK(err, expr, check_err) \
        bool _oom_result; \
        GCC_BEGIN_IGNORED_WARNING(-Waddress) \
        jw_err *_oom_err = (NULL != err) ? err : NULL; \
        GCC_END_IGNORED_WARNING(-Waddress) \
        if (_oom_err) { _oom_err->code = JW_ERR_NONE; } \
        oom_set_enabled(true); \
        oom_data->jwcAllocLimit = _oom_idx; \
        _oom_result = (expr); \
        fct_chk(!check_err || !_oom_result); \
        if (check_err && _oom_err) { \
            if (_oom_err->code != JW_ERR_NO_MEMORY) { \
                jw_log(JW_LOG_ERROR, \
                       "unexpected error value (%d) on iteration %d", \
                       _oom_err->code, _oom_idx + 1); \
            } \
            fct_chk_eq_int(_oom_err->code, JW_ERR_NO_MEMORY);\
        } \
    } \
    oom_set_enabled(false); \
}

#define OOM_TEST(err, expr) OOM_TEST_CONDITIONAL_CHECK(err, (expr), true)
#define OOM_TEST_NO_CHECK(err, expr) \
        OOM_TEST_CONDITIONAL_CHECK(err, (expr), false)

/**
 * OOM_SIMPLE_TEST is given the expression to test and assumes no intermediate
 * cleanup is required. The macro defines the jw_err "err" that the test
 * function *must* use (err->code is checked to make sure it was set correctly).
 * The given expression is executed successfully exactly one time.
 *
 * A simple test to check DOM context construction might look like:
 *
 *  jw_dom_ctx      ctx;
 *
 *  OOM_SIMPLE_TEST(jw_dom_context_create(&ctx, &err));
 *  jw_dom_context_destroy(ctx);
 */
#define OOM_SIMPLE_TEST_CONDITIONAL_CHECK(expr, check_err) \
{ \
    jw_err err; \
    OOM_RECORD_ALLOCS((expr)) \
    OOM_TEST_INIT() \
    OOM_TEST_CONDITIONAL_CHECK(&err, (expr), check_err) \
}

#define OOM_SIMPLE_TEST(expr) OOM_SIMPLE_TEST_CONDITIONAL_CHECK((expr), true)
#define OOM_SIMPLE_TEST_NO_CHECK(expr) \
        OOM_SIMPLE_TEST_CONDITIONAL_CHECK((expr), false)


/**
 * If a function uses a jw_pool its OOM tests should be wrapped in this macro.
 * NOTE: Any initialization and destruction logic should be included between
 * OOM_POOL_TEST_BGN && OOM_POOL_TEST_END. This will ensure pre-allocation
 * logic gets fully excercised.
 */
#define OOM_POOL_TEST_BGN \
    for(size_t itrs=0; itrs < 2; ++itrs) \
    { \
        jw_pool_enable_paging(itrs == 0); \

/**
 * The end pair of OOM_POOL_TEST_BGN
 */
#define OOM_POOL_TEST_END \
    } \
    jw_pool_enable_paging(true);

// returns whether two doms are syntactically equal
bool _dom_equal(jw_dom_node *expected,
                jw_dom_node *actual, bool deep);

// generic memory allocation/free counting functions
void     _test_init_counting_memory_funcs();
uint32_t _test_get_malloc_count();
uint32_t _test_get_free_count();
void     _test_uninit_counting_memory_funcs();

// clears config and populates it with good test defaults.  this is called by
// _test_init but is available directly if needed.  echosrv can be NULL.
bool _test_init_config(
        jw_htable *config, struct event_base *evbase,
        jw_test_echosrv echosrv);

// adds the port from the given echosrv to the config.  this is called by
// _test_init but is available directly if needed.  echosrv can be NULL.
bool _test_config_set_echosrv_port(
        jw_htable *config, jw_test_echosrv echosrv);

// clears the timedOut flag and creates a new event timer that will cause the
// libevent event loop to exit after the specified number of seconds.  this is
// called by _test_init but is available directly if needed
bool _test_init_failsafe(struct event_base *evbase,
                         struct event     **failsafeEvent,
                         uint32_t           numSeconds);

// retrieves whether the failsafe event fired since the last call to
// _test_init_failsafe
bool _test_get_timed_out();

// creates and initializes an event base, failsafe event (pass NULL if not
// needed), config, workq, and echosrv (pass NULL if not needed)
bool _test_init(struct event_base **evbase, struct event **failsafeEvent,
                jw_htable **config, jw_workq **workq,
                jw_test_echosrv *echosrv);

// destroys objects created in _test_init().  it is safe to pass NULL for any
// parameter
void _test_cleanup(struct event_base *evbase, struct event *failsafeEvent,
                   jw_htable *config, jw_workq *workq,
                   jw_test_echosrv echosrv);

#endif  // TEST_UTILS_H
