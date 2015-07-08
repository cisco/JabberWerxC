/**
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

#include "fct.h"
#include "test_utils.h"

#include <jabberwerx/util/states.h>


typedef struct
{
    bool event0_1, event0_2, event0_3;
    bool event1_1, event1_2, event1_3;
    bool event2_1;
} _called;


// verifies that the specified field is the only true value in the struct
static bool _verify_called(_called *called, bool *true_val)
{
    return called->event0_1 == (&called->event0_1 == true_val) &&
           called->event0_2 == (&called->event0_2 == true_val) &&
           called->event0_3 == (&called->event0_3 == true_val) &&
           called->event1_1 == (&called->event1_1 == true_val) &&
           called->event1_2 == (&called->event1_2 == true_val) &&
           called->event1_3 == (&called->event1_3 == true_val) &&
           called->event2_1 == (&called->event2_1 == true_val);
}

static void _on_event_transition(jw_event_data evt, void *arg)
{
    jw_states_event_data *evdata = evt->data;

    jw_state_val prev_state = jw_states_event_data_get_prev(evdata);
    jw_state_val next_state = jw_states_event_data_get_next(evdata);
    if (prev_state == next_state)
    {
        jw_log(JW_LOG_ERROR, "illegal state transition to same state: %d",
               next_state);
        assert(false);
    }

    jw_state_val *next = arg;
    if (NULL != next)
    {
        *next = next_state;
    }

    bool *called = jw_states_event_data_get_extra(evdata);
    if (NULL != called)
    {
        *called = true;
    }
}

static void _on_event(jw_event_data evt, void *arg)
{
    UNUSED_PARAM(evt);

    bool *called = arg;
    if (NULL != called)
    {
        *called = true;
    }
}

// same action as _on_event, but different memory address so it counts as a
// different callback
static void _on_event2(jw_event_data evt, void *arg)
{
    _on_event(evt, arg);
}

static void _extra_cleaner(void *ptr)
{
    UNUSED_PARAM(ptr);
}


static jw_loglevel _initlevel;
FCTMF_FIXTURE_SUITE_BGN(states_test)
{
    FCT_SETUP_BGN()
    {
        _initlevel = jw_log_get_level();
        _test_init_counting_memory_funcs();
    } FCT_SETUP_END()

    FCT_TEARDOWN_BGN()
    {
        fct_chk_eq_int(_test_get_free_count(), _test_get_malloc_count());
        if (_test_get_free_count() != _test_get_malloc_count())
        {
            jw_log(JW_LOG_ERROR, "memory leak: %u allocations, %u frees",
                   _test_get_malloc_count(), _test_get_free_count());
        }
        _test_uninit_counting_memory_funcs();
        jw_log_set_level(_initlevel);
    } FCT_TEARDOWN_END()

    FCT_TEST_BGN(jw_states_create)
    {
        //jw_log_set_level(JW_LOG_TRACE);

        jw_states          *states;
        const char        *names[] = { "state1", "state2", "state3", NULL };
        const char        *names0[] = { NULL };
        struct event_base *evbase;
        jw_htable          *config;
        jw_workq           *workq;
        jw_err             err;

        fct_req(_test_init(&evbase, NULL, &config, &workq, NULL));

        // basic happy creation
        fct_req(jw_states_create(names, 0, workq, &states, NULL));
        jw_states_destroy(states);

        // test ranges
        err.code = JW_ERR_NONE;
        fct_chk(!jw_states_create(names, -1, workq, &states, &err));
        fct_chk_eq_int(JW_ERR_INVALID_ARG, err.code);
        err.code = JW_ERR_NONE;
        fct_chk(!jw_states_create(names, 3, workq, &states, &err));
        fct_chk_eq_int(JW_ERR_INVALID_ARG, err.code);
        err.code = JW_ERR_NONE;
        fct_chk(!jw_states_create(names0, 0, workq, &states, &err));
        fct_chk_eq_int(JW_ERR_INVALID_ARG, err.code);

        int arr_size = 257;
        const char **names256 = jw_data_malloc(arr_size * sizeof(char *));
        for (int idx = 0; idx < arr_size; ++idx)
        {
            names256[idx] = "generic";
        }
        names256[arr_size-1] = NULL;
        err.code = JW_ERR_NONE;
        fct_chk(!jw_states_create(names256, 255, workq, &states, NULL));
        fct_chk(!jw_states_create(names256, 255, workq, &states, &err));
        fct_chk_eq_int(JW_ERR_INVALID_ARG, err.code);

        names256[arr_size-2] = NULL;
        err.code = JW_ERR_NONE;
        fct_chk(!jw_states_create(names256, 255, workq, &states, NULL));
        fct_chk(!jw_states_create(names256, 255, workq, &states, &err));
        fct_chk_eq_int(JW_ERR_INVALID_ARG, err.code);

        fct_req(jw_states_create(names256, 254, workq, &states, NULL));
        jw_states_destroy(states);
        jw_data_free(names256);

        // OOM testing
        OOM_SIMPLE_TEST(jw_states_create(names, 0, workq, &states, &err));
        jw_states_destroy(states);

        // repeat OOM test with NULL error for coverage (using alloc count from
        // OOM_SIMPLE_TEST); no need to destroy states since creation never
        // succeeds
        OOM_TEST_INIT();
        OOM_TEST(NULL, jw_states_create(names, 0, workq, &states, NULL));

        _test_cleanup(evbase, NULL, config, workq, NULL);
    } FCT_TEST_END()

    FCT_TEST_BGN(jw_states_state_attributes)
    {
        //jw_log_set_level(JW_LOG_TRACE);

        jw_states *states;
        const char *names[] = { "state1", "state2", "state3", NULL };
        struct event_base *evbase;
        jw_htable          *config;
        jw_workq           *workq;

        fct_req(_test_init(&evbase, NULL, &config, &workq, NULL));
        fct_req(jw_states_create(names, 0, workq, &states, NULL));

        fct_chk_eq_int(0, jw_states_get_current(states));
        fct_chk_eq_str("state1", jw_states_get_name_for(states, 0));
        fct_chk_eq_str("state3", jw_states_get_name_for(states, 2));
        fct_chk_eq_str(NULL, jw_states_get_name_for(states, 3));

        jw_states_destroy(states);
        _test_cleanup(evbase, NULL, config, workq, NULL);
    } FCT_TEST_END()

    FCT_TEST_BGN(jw_states_transition)
    {
        //jw_log_set_level(JW_LOG_TRACE);

        jw_states *states;
        const char *names[] = { "state1", "state2", "state3", NULL };
        struct event_base *evbase;
        struct event      *failsafeEvent;
        jw_htable          *config;
        jw_workq           *workq;
        jw_err err;

        jw_state_val next;
        bool called = false;

        fct_req(_test_init(&evbase, &failsafeEvent, &config, &workq, NULL));
        fct_req(jw_states_create(names, 0, workq, &states, NULL));
        fct_chk(jw_event_bind(jw_states_event(states, JW_STATES_EVENT),
                              _on_event_transition, &next, NULL));

        fct_chk_eq_int(0, jw_states_get_current(states));
        err.code = JW_ERR_NONE;
        fct_chk(!jw_states_change(states, -1, &called, NULL, NULL));
        fct_chk(!called);
        fct_chk(!jw_states_change(states, -1, &called, NULL, &err));
        fct_chk(!called);
        fct_chk_eq_int(JW_ERR_INVALID_ARG, err.code);
        err.code = JW_ERR_NONE;
        fct_chk(!jw_states_change(states, 3, &called, NULL, &err));
        fct_chk(!called);
        fct_chk_eq_int(JW_ERR_INVALID_ARG, err.code);

        fct_chk_eq_int(0, jw_states_get_current(states));
        fct_chk(jw_states_change(states, 2, &called, _extra_cleaner, NULL));
        event_base_loop(evbase, EVLOOP_NONBLOCK);
        fct_chk(called && !_test_get_timed_out());
        fct_chk_eq_int(2, next);
        called = false;
        fct_chk_eq_int(2, jw_states_get_current(states));
        fct_chk(jw_states_change(states, 2, &called, NULL, NULL));
        event_base_loop(evbase, EVLOOP_NONBLOCK);
        fct_chk(!called && !_test_get_timed_out());
        fct_chk_eq_int(2, jw_states_get_current(states));

        // OOM testing
        fct_chk_neq_int(0, jw_states_get_current(states));
        OOM_RECORD_ALLOCS(jw_states_change(states, 0, NULL, NULL, &err));
        event_base_loop(evbase, EVLOOP_NONBLOCK);
        fct_req(!_test_get_timed_out());
        fct_chk_eq_int(0, jw_states_get_current(states));
        fct_chk(jw_states_change(states, 1, NULL, NULL, NULL));
        event_base_loop(evbase, EVLOOP_NONBLOCK);
        fct_req(!_test_get_timed_out());
        OOM_TEST_INIT();
        OOM_TEST(&err, jw_states_change(states, 0, NULL, NULL, &err));
        event_base_loop(evbase, EVLOOP_NONBLOCK);
        fct_req(!_test_get_timed_out());
        fct_chk_neq_int(0, jw_states_get_current(states));
        OOM_TEST_INIT();
        OOM_TEST(NULL, jw_states_change(states, 0, NULL, NULL, NULL));
        event_base_loop(evbase, EVLOOP_NONBLOCK);
        fct_req(!_test_get_timed_out());
        fct_chk_neq_int(0, jw_states_get_current(states));

        jw_states_destroy(states);
        _test_cleanup(evbase, failsafeEvent, config, workq, NULL);
    } FCT_TEST_END()

    FCT_TEST_BGN(jw_states_register_for)
    {
        //jw_log_set_level(JW_LOG_TRACE);

        jw_states *states;
        const char *names[] = { "st1", "st2", "st3", "st4", "st5", NULL };
        struct event_base *evbase;
        struct event      *failsafeEvent;
        jw_htable          *config;
        jw_workq           *workq;
        void *fake_source = jw_data_malloc(1);
        jw_event_dispatcher *dispatch;
        jw_event *event;
        jw_err err;

        fct_req(_test_init(&evbase, &failsafeEvent, &config, &workq, NULL));
        fct_req(jw_states_create(names, 1, workq, &states, NULL));
        fct_req(jw_event_dispatcher_create(fake_source, NULL, &dispatch, NULL));
        fct_req(jw_event_dispatcher_create_event(
                        dispatch, "event", &event, NULL));

        err.code = JW_ERR_NONE;
        fct_chk(!jw_states_register_for(states, -1, event, _on_event, NULL, NULL));
        fct_chk(!jw_states_register_for(states, -1, event, _on_event, NULL, &err));
        fct_chk_eq_int(JW_ERR_INVALID_ARG, err.code);

        fct_chk_neq_int(0, jw_states_get_current(states));
        fct_chk(jw_states_register_for(states, 0, event, _on_event, NULL, NULL));
        fct_chk_eq_int(1, jw_states_get_current(states));
        fct_chk(jw_states_register_for(states, 1, event, _on_event, NULL, NULL));

        // OOM testing
        fct_chk(jw_states_change(states, 2, NULL, NULL, NULL));
        event_base_loop(evbase, EVLOOP_NONBLOCK);
        fct_req(!_test_get_timed_out());
        OOM_RECORD_ALLOCS(jw_states_register_for(states, 2, event, _on_event, NULL, &err));
        // we need a fresh "current" state in order to follow the same code path
        fct_chk(jw_states_change(states, 3, NULL, NULL, NULL));
        event_base_loop(evbase, EVLOOP_NONBLOCK);
        fct_req(!_test_get_timed_out());
        OOM_TEST_INIT();
        OOM_TEST(&err, jw_states_register_for(states, 3, event, _on_event, NULL, &err));
        fct_chk(jw_states_change(states, 4, NULL, NULL, NULL));
        event_base_loop(evbase, EVLOOP_NONBLOCK);
        fct_req(!_test_get_timed_out());
        OOM_TEST_INIT();
        OOM_TEST(NULL, jw_states_register_for(states, 4, event, _on_event, NULL, NULL));

        jw_states_destroy(states);
        jw_data_free(fake_source);
        jw_event_dispatcher_destroy(dispatch);
        _test_cleanup(evbase, failsafeEvent, config, workq, NULL);
    } FCT_TEST_END()

    FCT_TEST_BGN(jw_states_events)
    {
        //jw_log_set_level(JW_LOG_TRACE);

        jw_states *states;
        const char *names[] = { "state1", "state2", "state3", NULL };
        void *fake_source = jw_data_malloc(1);
        jw_event_dispatcher *dispatch;
        jw_event *event0_1_and_2_1, *event0_2_and_1_2, *event0_3_and_1_1;
        jw_event *event1_3;
        struct event_base *evbase;
        struct event      *failsafeEvent;
        jw_htable          *config;
        jw_workq           *workq;
        jw_err err;
        jw_state_val next;
        bool transition_called;
        _called called;
        _called reset_called =
                { false, false, false, false, false, false, false };

        fct_req(_test_init(&evbase, &failsafeEvent, &config, &workq, NULL));
        fct_req(jw_states_create(names, 2, workq, &states, NULL));
        fct_chk(jw_event_bind(jw_states_event(states, JW_STATES_EVENT),
                              _on_event_transition, &next, NULL));

        // create and link up events
        fct_req(jw_event_dispatcher_create(fake_source, NULL, &dispatch, NULL));

#define CREATE_EVENT(event) \
    fct_req(jw_event_dispatcher_create_event( \
                    dispatch, JW_STATES_NAME(event), &event, NULL))
        
        CREATE_EVENT(event0_1_and_2_1);
        CREATE_EVENT(event0_2_and_1_2);
        CREATE_EVENT(event0_3_and_1_1);
        CREATE_EVENT(event1_3);
#undef CREATE_EVENT

        fct_chk(jw_states_register_for(states, 0, event0_1_and_2_1, _on_event, &called.event0_1, NULL));
        fct_chk(jw_states_register_for(states, 0, event0_2_and_1_2, _on_event, &called.event0_2, NULL));
        fct_chk(jw_states_register_for(states, 0, event0_3_and_1_1, _on_event, &called.event0_3, NULL));
        fct_chk(jw_states_register_for(states, 1, event0_3_and_1_1, _on_event, &called.event1_1, NULL));
        fct_chk(jw_states_register_for(states, 1, event0_2_and_1_2, _on_event, &called.event1_2, NULL));
        fct_chk(jw_states_register_for(states, 1, event1_3, _on_event, &called.event1_3, NULL));
        fct_chk(jw_states_register_for(states, 2, event0_1_and_2_1, _on_event2, &called.event2_1, NULL));

        // ensure expected callbacks are called for each state.
        // order of callbacks may be unstable, so just test set membership
        // all state transition orders must be tested

#define VERIFY_STATE_0 \
    do { \
        called = reset_called; \
        fct_chk(jw_event_trigger(event0_1_and_2_1, NULL, NULL, NULL, NULL)); \
        fct_chk(_verify_called(&called, &called.event0_1)); \
        called = reset_called; \
        fct_chk(jw_event_trigger(event0_2_and_1_2, NULL, NULL, NULL, NULL)); \
        fct_chk(_verify_called(&called, &called.event0_2)); \
        called = reset_called; \
        fct_chk(jw_event_trigger(event0_3_and_1_1, NULL, NULL, NULL, NULL)); \
        fct_chk(_verify_called(&called, &called.event0_3)); \
        called = reset_called; \
        fct_chk(jw_event_trigger(event1_3, NULL, NULL, NULL, NULL)); \
        fct_chk(_verify_called(&called, NULL)); \
    } while (0)
#define VERIFY_STATE_1 \
    do { \
        called = reset_called; \
        fct_chk(jw_event_trigger(event0_1_and_2_1, NULL, NULL, NULL, NULL)); \
        fct_chk(_verify_called(&called, NULL)); \
        fct_chk(jw_event_trigger(event0_2_and_1_2, NULL, NULL, NULL, NULL)); \
        fct_chk(_verify_called(&called, &called.event1_2)); \
        called = reset_called; \
        fct_chk(jw_event_trigger(event0_3_and_1_1, NULL, NULL, NULL, NULL)); \
        fct_chk(_verify_called(&called, &called.event1_1)); \
        called = reset_called; \
        fct_chk(jw_event_trigger(event1_3, NULL, NULL, NULL, NULL)); \
        fct_chk(_verify_called(&called, &called.event1_3)); \
    } while (0)
#define VERIFY_STATE_2 \
    do { \
        called = reset_called; \
        fct_chk(jw_event_trigger(event0_1_and_2_1, NULL, NULL, NULL, NULL)); \
        fct_chk(_verify_called(&called, &called.event2_1)); \
        called = reset_called; \
        fct_chk(jw_event_trigger(event0_2_and_1_2, NULL, NULL, NULL, NULL)); \
        fct_chk(_verify_called(&called, NULL)); \
        fct_chk(jw_event_trigger(event0_3_and_1_1, NULL, NULL, NULL, NULL)); \
        fct_chk(_verify_called(&called, NULL)); \
        fct_chk(jw_event_trigger(event1_3, NULL, NULL, NULL, NULL)); \
        fct_chk(_verify_called(&called, NULL)); \
    } while (0)

        // state 2
        VERIFY_STATE_2;

        // state 2 -> 1
        transition_called = false;
        fct_chk(jw_states_change(states, 1, &transition_called, NULL, NULL));
        event_base_loop(evbase, EVLOOP_NONBLOCK);
        fct_req(!_test_get_timed_out());
        fct_chk(transition_called);
        fct_chk_eq_int(1, next);
        VERIFY_STATE_1;

        // state 1 -> 0
        transition_called = false;
        fct_chk(jw_states_change(states, 0, &transition_called, NULL, NULL));
        event_base_loop(evbase, EVLOOP_NONBLOCK);
        fct_req(!_test_get_timed_out());
        fct_chk(transition_called);
        fct_chk_eq_int(0, next);
        VERIFY_STATE_0;

        // state 0 -> 2
        transition_called = false;
        fct_chk(jw_states_change(states, 2, &transition_called, NULL, NULL));
        event_base_loop(evbase, EVLOOP_NONBLOCK);
        fct_req(!_test_get_timed_out());
        fct_chk(transition_called);
        fct_chk_eq_int(2, next);
        VERIFY_STATE_2;

        // state 2 -> 0
        transition_called = false;
        fct_chk(jw_states_change(states, 0, &transition_called, NULL, NULL));
        event_base_loop(evbase, EVLOOP_NONBLOCK);
        fct_req(!_test_get_timed_out());
        fct_chk(transition_called);
        fct_chk_eq_int(0, next);
        VERIFY_STATE_0;

        // state 0 -> 1
        transition_called = false;
        fct_chk(jw_states_change(states, 1, &transition_called, NULL, NULL));
        event_base_loop(evbase, EVLOOP_NONBLOCK);
        fct_req(!_test_get_timed_out());
        fct_chk(transition_called);
        fct_chk_eq_int(1, next);
        VERIFY_STATE_1;

        // state 1 -> 2
        transition_called = false;
        fct_chk(jw_states_change(states, 2, &transition_called, NULL, NULL));
        event_base_loop(evbase, EVLOOP_NONBLOCK);
        fct_req(!_test_get_timed_out());
        fct_chk(transition_called);
        fct_chk_eq_int(2, next);
        VERIFY_STATE_2;

        // OOM testing
        fct_chk(jw_states_change(states, 1, NULL, NULL, NULL));
        event_base_loop(evbase, EVLOOP_NONBLOCK);
        fct_req(!_test_get_timed_out());
        OOM_RECORD_ALLOCS(jw_states_change(states, 0, NULL, NULL, &err));
        event_base_loop(evbase, EVLOOP_NONBLOCK);
        fct_req(!_test_get_timed_out());
        fct_chk_eq_int(0, jw_states_get_current(states));
        VERIFY_STATE_0;

        fct_chk(jw_states_change(states, 1, NULL, NULL, NULL));
        event_base_loop(evbase, EVLOOP_NONBLOCK);
        fct_req(!_test_get_timed_out());
        OOM_TEST_INIT();
        OOM_TEST(&err, jw_states_change(states, 0, NULL, NULL, &err));
        event_base_loop(evbase, EVLOOP_NONBLOCK);
        fct_req(!_test_get_timed_out());
        fct_chk_eq_int(1, jw_states_get_current(states));
        fct_chk(jw_states_change(states, 1, NULL, NULL, NULL));
        event_base_loop(evbase, EVLOOP_NONBLOCK);
        fct_req(!_test_get_timed_out());
        VERIFY_STATE_1;

        OOM_TEST_INIT();
        OOM_TEST(NULL, jw_states_change(states, 0, NULL, NULL, NULL));
        event_base_loop(evbase, EVLOOP_NONBLOCK);
        fct_req(!_test_get_timed_out());
        fct_chk_eq_int(1, jw_states_get_current(states));
        VERIFY_STATE_1;

        fct_chk(jw_states_change(states, 0, NULL, NULL, NULL));
        event_base_loop(evbase, EVLOOP_NONBLOCK);
        fct_req(!_test_get_timed_out());
        OOM_RECORD_ALLOCS(jw_states_change(states, 1, NULL, NULL, &err));
        event_base_loop(evbase, EVLOOP_NONBLOCK);
        fct_req(!_test_get_timed_out());
        fct_chk_eq_int(1, jw_states_get_current(states));
        VERIFY_STATE_1;

        fct_chk(jw_states_change(states, 0, NULL, NULL, NULL));
        event_base_loop(evbase, EVLOOP_NONBLOCK);
        fct_req(!_test_get_timed_out());
        OOM_TEST_INIT();
        OOM_TEST(NULL, jw_states_change(states, 1, NULL, NULL, NULL));
        event_base_loop(evbase, EVLOOP_NONBLOCK);
        fct_req(!_test_get_timed_out());
        fct_chk_eq_int(0, jw_states_get_current(states));
        VERIFY_STATE_0;

        OOM_RECORD_ALLOCS(jw_states_change(states, 2, NULL, NULL, &err));
        event_base_loop(evbase, EVLOOP_NONBLOCK);
        fct_req(!_test_get_timed_out());
        fct_chk_eq_int(2, jw_states_get_current(states));
        VERIFY_STATE_2;

        fct_chk(jw_states_change(states, 0, NULL, NULL, NULL));
        event_base_loop(evbase, EVLOOP_NONBLOCK);
        fct_req(!_test_get_timed_out());
        OOM_TEST_INIT();
        OOM_TEST(NULL, jw_states_change(states, 2, NULL, NULL, NULL));
        event_base_loop(evbase, EVLOOP_NONBLOCK);
        fct_req(!_test_get_timed_out());
        fct_chk_eq_int(0, jw_states_get_current(states));
        VERIFY_STATE_0;

        fct_chk(jw_states_change(states, 2, NULL, NULL, NULL));
        event_base_loop(evbase, EVLOOP_NONBLOCK);
        fct_req(!_test_get_timed_out());
        OOM_RECORD_ALLOCS(jw_states_change(states, 0, NULL, NULL, &err));
        event_base_loop(evbase, EVLOOP_NONBLOCK);
        fct_req(!_test_get_timed_out());
        fct_chk_eq_int(0, jw_states_get_current(states));
        VERIFY_STATE_0;

        fct_chk(jw_states_change(states, 2, NULL, NULL, NULL));
        event_base_loop(evbase, EVLOOP_NONBLOCK);
        fct_req(!_test_get_timed_out());
        OOM_TEST_INIT();
        OOM_TEST(NULL, jw_states_change(states, 0, NULL, NULL, NULL));
        event_base_loop(evbase, EVLOOP_NONBLOCK);
        fct_req(!_test_get_timed_out());
        fct_chk_eq_int(2, jw_states_get_current(states));
        VERIFY_STATE_2;

#undef VERIFY_STATE_0
#undef VERIFY_STATE_1
#undef VERIFY_STATE_2

        jw_states_destroy(states);

        // ensure that everything is unbound after destruction
        called = reset_called;
        fct_chk(jw_event_trigger(event0_1_and_2_1, NULL, NULL, NULL, NULL));
        fct_chk(_verify_called(&called, NULL));
        fct_chk(jw_event_trigger(event0_2_and_1_2, NULL, NULL, NULL, NULL));
        fct_chk(_verify_called(&called, NULL));
        fct_chk(jw_event_trigger(event0_3_and_1_1, NULL, NULL, NULL, NULL));
        fct_chk(_verify_called(&called, NULL));
        fct_chk(jw_event_trigger(event1_3, NULL, NULL, NULL, NULL));
        fct_chk(_verify_called(&called, NULL));

        jw_data_free(fake_source);
        jw_event_dispatcher_destroy(dispatch);
        _test_cleanup(evbase, failsafeEvent, config, workq, NULL);
    } FCT_TEST_END()
} FCTMF_FIXTURE_SUITE_END()
