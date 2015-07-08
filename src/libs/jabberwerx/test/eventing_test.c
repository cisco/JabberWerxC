/**
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

#include "test_utils.h"
#include "../src/include/eventing_int.h"
#include <jabberwerx/util/mem.h>
#include <jabberwerx/eventing.h>
#include <jabberwerx/stream.h>
#include <event2/event.h>

#include <fct.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>


/* fake global source object */
static void *g_source = "the global source";
static jw_event_dispatcher  *g_dispatcher;

/* for auditing */
typedef struct _logitem_t
{
    const char          *message;
    struct _logitem_t   *next;
} logitem_t;
typedef struct _log_set_t
{
    unsigned int    count;
    logitem_t       *items;
    logitem_t       *itemsend;
    jw_pool         *pool;
} log_t;
typedef void (*fn_ptr_t)();
typedef struct _fn_ptr_wrapper
{
    fn_ptr_t fn;
} fn_ptr_wrapper_t;

static log_t    g_audit;

static const char *log_event_message(const char *cb,
                                     jw_event *notifier,
                                     void *evtdata,
                                     void *evtarg)
{
    char        text[1024];
    const char  *out;

    sprintf(text, "%s:%s (notifier=0x%p; source=0x%p; data=0x%p; arg=0x%p)",
                  cb,
                  jw_event_get_name(notifier),
                  (void *)notifier,
                  jw_event_get_source(notifier),
                  evtdata,
                  evtarg);

    if (!jw_pool_strdup(g_audit.pool, text, (char **)&out, NULL))
    {
        return NULL;
    }

    return out;
}
static const char *log_result_message(const char *cb,
                                      jw_event *notifier,
                                      void *evtdata,
                                      bool result,
                                      void *rstarg)
{
    char        text[1024];
    const char  *out;

    sprintf(text, "%s:%s == %s (notifier=0x%p; source=0x%p; data=0x%p; arg=0x%p)",
                  cb,
                  jw_event_get_name(notifier),
                  (result ? "true" : "false"),
                  (void *)notifier,
                  jw_event_get_source(notifier),
                  evtdata,
                  rstarg);

    if (!jw_pool_strdup(g_audit.pool, text, (char **)&out, NULL))
    {
        return NULL;
    }

    return out;
}
static void loggit(const char *msg)
{
    union
    {
        logitem_t *item;
        void      *itemPtr;
    } itemUnion;

    if (!jw_pool_malloc(g_audit.pool, sizeof(logitem_t), &itemUnion.itemPtr, NULL))
    {
        return;
    }

    logitem_t *item = itemUnion.item;
    item->message = msg;
    item->next = NULL;

    if (g_audit.items == NULL)
    {
        g_audit.items = item;
    }
    else
    {
        g_audit.itemsend->next = item;
    }
    g_audit.itemsend = item;
    g_audit.count++;
}

/**
 * Event callback updates log with actual data
 */
static void mock_evt1_callback1(jw_event_data evt, void *arg)
{
    evt->handled = true;

    const char  *msg = log_event_message("mock_evt1_callback1",
                                         evt->notifier,
                                         evt->data,
                                         arg);
    loggit(msg);
}

/**
 * Event callback that unbinds mock_evt1_callback1 during the event to defer
 * it.  This is used in conjunction with mock_evt_rebind1_callback1 which will
 * re-add mock_evt1_callback1 before its deferred removal.
 */
static void mock_evt_unbind1_callback1(jw_event_data evt, void *arg)
{
    const char *msg = log_event_message("mock_evt_unbind1_callback1",
                                        evt->notifier,
                                        evt->data,
                                        arg);
    loggit(msg);

    jw_event_unbind(evt->notifier, mock_evt1_callback1);
}
static void mock_evt_rebind1_callback1(jw_event_data evt, void *arg)
{
    const char *msg = log_event_message("mock_evt_rebind1_callback1",
                                        evt->notifier,
                                        evt->data,
                                        arg);
    loggit(msg);

    jw_event_bind(evt->notifier, mock_evt1_callback1, NULL, NULL);
}

/**
 * Event callback that unbinds event while being triggered
 *
 * Next for functions are essentially the same, just different names
 * so they can bind to the same event
 */
static void mock_evt_unbind_callback1(jw_event_data evt, void *arg)
{
    const char *msg = log_event_message("mock_evt_unbind_callback1",
                                        evt->notifier,
                                        evt->data,
                                        arg);
    loggit(msg);

    jw_event_unbind(evt->notifier, mock_evt_unbind_callback1);
}
static void mock_evt_unbind_callback2(jw_event_data evt, void *arg)
{
    const char *msg = log_event_message("mock_evt_unbind_callback2",
                                        evt->notifier,
                                        evt->data,
                                        arg);
    loggit(msg);

    // try unbinding twice (second is a noop)
    jw_event_unbind(evt->notifier, mock_evt_unbind_callback2);
    jw_event_unbind(evt->notifier, mock_evt_unbind_callback2);
}
static void mock_evt_unbind_callback3(jw_event_data evt, void *arg)
{
    const char *msg = log_event_message("mock_evt_unbind_callback3",
                                        evt->notifier,
                                        evt->data,
                                        arg);
    loggit(msg);

    jw_event_unbind(evt->notifier, mock_evt_unbind_callback3);
}
static void mock_evt_unbind_callback4(jw_event_data evt, void *arg)
{
    const char *msg = log_event_message("mock_evt_unbind_callback4",
                                        evt->notifier,
                                        evt->data,
                                        arg);
    loggit(msg);

    jw_event_unbind(evt->notifier, mock_evt_unbind_callback4);
}

/**
 * Event callback updates log with actual data, and marks the event handled
 */
static void mock_evt1_callback_handled1(jw_event_data evt, void *arg)
{
    const char  *msg = log_event_message("mock_evt1_callback_handled1",
                                         evt->notifier,
                                         evt->data,
                                         arg);
    loggit(msg);
    evt->handled = true;
}

/**
 * Event callback updates log with actual data
 */
static void mock_evt1_callback2(jw_event_data evt, void *arg)
{
    const char  *msg = log_event_message("mock_evt1_callback2",
                                         evt->notifier,
                                         evt->data,
                                         arg);
    loggit(msg);
}

/**
 * Result callback updates log with actual data
 */
static void mock_evt1_result1(jw_event_data evt, bool result, void *arg)
{
    const char  *msg = log_result_message("mock_evt1_result1",
                                          evt->notifier,
                                          evt->data,
                                          result,
                                          arg);
    loggit(msg);
}


/**
 * nesting_callbackA triggers event "arg" using result callback "evt->data"
 */
static void nesting_callbackA(jw_event_data evt, void *arg)
{
    fn_ptr_wrapper_t * wrapper = (fn_ptr_wrapper_t *)evt->data;
    jw_event_result_callback callback = NULL;
    if (NULL != wrapper)
    {
        callback = (jw_event_result_callback)wrapper->fn;
    }
    /* trigger first to check recursion */
    jw_event_trigger((jw_event*)arg, NULL, callback, NULL, NULL);
    loggit(log_event_message("nesting_callbackA",
                             evt->notifier,
                             evt->data,
                             arg));
}
// same as above, but fires two arg events instead of one
static void double_nesting_callback(jw_event_data evt, void *arg)
{
    fn_ptr_wrapper_t * wrapper = (fn_ptr_wrapper_t *)evt->data;
    jw_event_result_callback callback = NULL;
    if (NULL != wrapper)
    {
        callback = (jw_event_result_callback)wrapper->fn;
    }
    /* trigger first to check recursion */
    jw_event_trigger((jw_event*)arg, NULL, callback, NULL, NULL);
    jw_event_trigger((jw_event*)arg, NULL, callback, NULL, NULL);
    loggit(log_event_message("double_nesting_callback",
                             evt->notifier,
                             evt->data,
                             arg));
}
static void nesting_callbackB(jw_event_data evt, void *arg)
{
    loggit(log_event_message("nesting_callbackB",
                             evt->notifier,
                             evt->data,
                             arg));
}
/* sets handled to true */
static void nesting_callbackC(jw_event_data evt, void *arg)
{
    loggit(log_event_message("nesting_callbackC",
                             evt->notifier,
                             evt->data,
                             arg));
    evt->handled = true;
}
static void nesting_resultA(jw_event_data evt, bool result, void *arg)
{
    loggit(log_result_message("nesting_resultA",
                              evt->notifier,
                              evt->data,
                              result,
                              arg));
}
static void nesting_resultB(jw_event_data evt, bool result, void *arg)
{
    loggit(log_result_message("nesting_resultB",
                              evt->notifier,
                              evt->data,
                              result,
                              arg));
}


/*
 callbackA and callbackC are passed the event to be fired
 as a bound argument.
*/
static void evt1_callbackA(jw_event_data evt, void *arg)
{
    const char  *msg = log_event_message("evt1_callbackA",
                                         evt->notifier,
                                         evt->data,
                                         arg);
    /* arg is evt2*/
    loggit(msg);
    jw_event_trigger((jw_event*)arg, NULL, NULL, NULL, NULL);
}
static void evt3_callbackB(jw_event_data evt, void *arg)
{
    const char  *msg = log_event_message("evt3_callbackB",
                                         evt->notifier,
                                         evt->data,
                                         arg);
    loggit(msg);
}
static void evt2_callbackC(jw_event_data evt, void *arg)
{
    const char  *msg = log_event_message("evt2_callbackC",
                                         evt->notifier,
                                         evt->data,
                                         arg);
    /* arg is evt3 */
    loggit(msg);
    jw_event_trigger((jw_event*)arg, NULL, NULL, NULL, NULL);
}
static void evt2_callbackD(jw_event_data evt, void *arg)
{
    const char  *msg = log_event_message("evt2_callbackD",
                                         evt->notifier,
                                         evt->data,
                                         arg);
    loggit(msg);
}

/**
 * 
 * Event callback that binds event while being triggered
 *
 */
static void mock_evt_bind1_callback1(jw_event_data evt, void *arg)
{
    const char *msg = log_event_message("mock_evt_bind1_callback1",
                                        evt->notifier,
                                        evt->data,
                                        arg);
    loggit(msg);

    jw_event_bind(evt->notifier, mock_evt1_callback1, NULL, NULL);
}
static void mock_evt_bind1_callback2(jw_event_data evt, void *arg)
{
    const char *msg = log_event_message("mock_evt_bind1_callback2",
                                        evt->notifier,
                                        evt->data,
                                        arg);
    loggit(msg);

    jw_event_bind(evt->notifier, mock_evt1_callback2, NULL, NULL);
}

static int _mallocCnt = 0;
static void *_counting_malloc(size_t size)
{
    ++_mallocCnt;
    return malloc(size);
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
    ++_freeCnt;
    free(ptr);
}

static bool g_oom_malloc_called = false;
static void * mock_oom_malloc(size_t size)
{
    UNUSED_PARAM(size);
    g_oom_malloc_called = true;
    return NULL;
}
static void * mock_oom_realloc(void * ptr, size_t size)
{
    UNUSED_PARAM(ptr);
    UNUSED_PARAM(size);
    g_oom_malloc_called = true;
    return NULL;
}
static bool g_nofail_callback_called = false;
static void mock_nofail_callback(jw_event_data evt, void *arg)
{
    UNUSED_PARAM(evt);
    UNUSED_PARAM(arg);
    g_nofail_callback_called = true;
}

void * g_destroy_first_alloc = NULL;
static void * destroy_test_malloc(size_t size)
{
    void * ret = malloc(size);
    if (!g_destroy_first_alloc)
    {
        g_destroy_first_alloc = ret;
    }
    return ret;
}
static bool g_destroy_correctly_deferred = false;
static bool g_destroy_first_free = false;
static void destroy_test_free(void * ptr)
{
    if (ptr && ptr == g_destroy_first_alloc)
    {
        // record if the remembered pointer was freed
        g_destroy_first_free = true;
    }
    free(ptr);
}
static void destroying_callback(jw_event_data evt, void *arg)
{
    jw_event            *next_evt   = evt->data;
    jw_event_dispatcher *dispatcher = arg;
    
    if (next_evt)
    {
        if (!jw_event_trigger(next_evt, NULL, NULL, NULL, NULL))
        {
            jw_log(JW_LOG_DEBUG, "event trigger failed in destroying_callback");
        }
    }

    g_destroy_correctly_deferred = true;
    jw_event_dispatcher_destroy(dispatcher);
    if (g_destroy_first_free)
    {
        jw_log(JW_LOG_ERROR, "dispatcher destruction not correctly deferred"
                             " in destroying_callback");
        g_destroy_correctly_deferred = false;
    }
}

static void async_callback(jw_event_data evt, void *arg)
{
    UNUSED_PARAM(arg);

    uint32_t *call_count = evt->data;
    ++*call_count;
}


FCTMF_FIXTURE_SUITE_BGN(eventing_test)
{
    FCT_SETUP_BGN()
    {
        jw_event    *mock1, *mock2;

        memset(&g_audit, 0, sizeof(log_t));
        jw_pool_create(0, &g_audit.pool, NULL);

        jw_event_dispatcher_create(g_source, NULL, &g_dispatcher, NULL);
        jw_event_dispatcher_create_event(g_dispatcher,
                                         "mockEvent1",
                                         &mock1,
                                         NULL);
        jw_event_dispatcher_create_event(g_dispatcher,
                                         "mockEvent2",
                                         &mock2,
                                         NULL);
    } FCT_SETUP_END()

    FCT_TEARDOWN_BGN()
    {
        jw_event_dispatcher_destroy(g_dispatcher);
        g_dispatcher = NULL;

        /* reset audit trail */
        jw_pool_destroy(g_audit.pool);
        memset(&g_audit, 0, sizeof(log_t));
    } FCT_TEARDOWN_END()

    FCT_TEST_BGN(jw_event_dispatcher_create_destroy)
    {
        jw_event_dispatcher *dispatch;
        jw_err              err;
        void                *source = "the source";

        fct_chk(jw_event_dispatcher_create(source, NULL, &dispatch, &err));
        fct_chk(dispatch->source == source);
        fct_chk(dispatch->events != NULL);
        fct_chk(dispatch->running == false);
        fct_chk(dispatch->moment_queue_tail == NULL);

        jw_event_dispatcher_destroy(dispatch);
    } FCT_TEST_END()
    FCT_TEST_BGN(jw_event_create)
    {
        jw_event        *evt1, *evt2, *evt3;
        jw_err          err;

        fct_chk(jw_event_dispatcher_get_event(g_dispatcher, "EventOne") == NULL);
        fct_chk(jw_event_dispatcher_get_event(g_dispatcher, "eventOne") == NULL);
        fct_chk(jw_event_dispatcher_get_event(g_dispatcher, "eventone") == NULL);
        fct_chk(jw_event_dispatcher_get_event(g_dispatcher, "EVENTONE") == NULL);
        fct_chk(jw_event_dispatcher_get_event(g_dispatcher, "SecondEvent") == NULL);
        fct_chk(jw_event_dispatcher_get_event(g_dispatcher, "secondEvent") == NULL);
        fct_chk(jw_event_dispatcher_get_event(g_dispatcher, "secondevent") == NULL);
        fct_chk(jw_event_dispatcher_get_event(g_dispatcher, "SECONDEVENT") == NULL);

        fct_req(jw_event_dispatcher_create_event(g_dispatcher,
                                                 "eventOne",
                                                 &evt1,
                                                 &err) == true);
        fct_chk(evt1->dispatcher == g_dispatcher);
        fct_chk(evt1->bindings == NULL);
        fct_chk_eq_str(jw_event_get_name(evt1), "eventOne");
        fct_chk(jw_event_get_source(evt1) == g_source);
        fct_chk(jw_event_dispatcher_get_event(g_dispatcher, "EventOne") == evt1);
        fct_chk(jw_event_dispatcher_get_event(g_dispatcher, "eventOne") == evt1);
        fct_chk(jw_event_dispatcher_get_event(g_dispatcher, "eventone") == evt1);
        fct_chk(jw_event_dispatcher_get_event(g_dispatcher, "EVENTONE") == evt1);
        fct_chk(jw_event_dispatcher_get_event(g_dispatcher, "SecondEvent") == NULL);
        fct_chk(jw_event_dispatcher_get_event(g_dispatcher, "secondEvent") == NULL);
        fct_chk(jw_event_dispatcher_get_event(g_dispatcher, "secondevent") == NULL);
        fct_chk(jw_event_dispatcher_get_event(g_dispatcher, "SECONDEVENT") == NULL);

        fct_req(jw_event_dispatcher_create_event(g_dispatcher,
                                                 "secondEvent",
                                                 &evt2,
                                                 &err) == true);
        fct_chk(evt2->dispatcher == g_dispatcher);
        fct_chk(evt2->bindings == NULL);
        fct_chk_eq_str(jw_event_get_name(evt2), "secondEvent");
        fct_chk(jw_event_get_source(evt2) == g_source);
        fct_chk(jw_event_dispatcher_get_event(g_dispatcher, "EventOne") == evt1);
        fct_chk(jw_event_dispatcher_get_event(g_dispatcher, "eventOne") == evt1);
        fct_chk(jw_event_dispatcher_get_event(g_dispatcher, "eventone") == evt1);
        fct_chk(jw_event_dispatcher_get_event(g_dispatcher, "EVENTONE") == evt1);
        fct_chk(jw_event_dispatcher_get_event(g_dispatcher, "SecondEvent") == evt2);
        fct_chk(jw_event_dispatcher_get_event(g_dispatcher, "secondEvent") == evt2);
        fct_chk(jw_event_dispatcher_get_event(g_dispatcher, "secondevent") == evt2);
        fct_chk(jw_event_dispatcher_get_event(g_dispatcher, "SECONDEVENT") == evt2);
        fct_chk(evt1 != evt2);

        // create an event but only retrieve the pointer indirectly
        fct_req(jw_event_dispatcher_create_event(g_dispatcher, "eventTheThird",
                                                 NULL, NULL));
        evt3 = jw_event_dispatcher_get_event(g_dispatcher, "eventTheThird");
        fct_req(NULL != evt3);
        fct_chk(evt1 != evt3);
        fct_chk(evt2 != evt3);
    } FCT_TEST_END()
    FCT_TEST_BGN(jw_event_bindings)
    {
        jw_event            *evt1;
        jw_err              err;
        jw_event_binding_t  *b;
        void                *arg1, *arg2;

        evt1 = jw_event_dispatcher_get_event(g_dispatcher, "mockEvent1");
        fct_chk(evt1->bindings == NULL);

        // ensure unbinding when nothing is bound doesn't segfault
        jw_event_unbind(evt1, mock_evt1_callback1);

        fct_req(jw_event_bind(evt1, mock_evt1_callback1, NULL, &err) == true);
        b = evt1->bindings;
        fct_chk(b != NULL);
        fct_chk(b->cb == mock_evt1_callback1);
        fct_chk(b->arg == NULL);
        fct_chk(b->next == NULL);

        jw_event_unbind(evt1, mock_evt1_callback1);
        fct_chk(evt1->bindings == NULL);

        arg1 = "first bound argument";
        fct_req(jw_event_bind(evt1, mock_evt1_callback1, arg1, &err) == true);
        b = evt1->bindings;
        fct_chk(b != NULL);
        fct_chk(b->cb == mock_evt1_callback1);
        fct_chk(b->arg == arg1);
        fct_chk(b->next == NULL);

        fct_req(jw_event_bind(evt1, mock_evt1_callback2, NULL, &err) == true);
        b = evt1->bindings;
        fct_req(b != NULL);
        fct_chk(b->cb == mock_evt1_callback1);
        fct_chk(b->arg == arg1);
        fct_chk(b->next != NULL);
        b = b->next;
        fct_req(b != NULL);
        fct_chk(b->cb == mock_evt1_callback2);
        fct_chk(b->arg == NULL);
        fct_chk(b->next == NULL);

        jw_event_unbind(evt1, mock_evt1_callback2);
        b = evt1->bindings;
        fct_req(b != NULL);
        fct_chk(b->cb == mock_evt1_callback1);
        fct_chk(b->arg == arg1);
        fct_chk(b->next == NULL);

        arg2 = "second bound argument";
        fct_req(jw_event_bind(evt1, mock_evt1_callback2, arg2, &err) == true);
        b = evt1->bindings;
        fct_req(b != NULL);
        fct_chk(b->cb == mock_evt1_callback1);
        fct_chk(b->arg == arg1);
        fct_chk(b->next != NULL);
        b = b->next;
        fct_req(b != NULL);
        fct_chk(b->cb == mock_evt1_callback2);
        fct_chk(b->arg == arg2);
        fct_chk(b->next == NULL);

        /* reregister; should not change position */
        fct_req(jw_event_bind(evt1, mock_evt1_callback1, NULL, &err) == true);
        b = evt1->bindings;
        fct_req(b != NULL);
        fct_chk(b->cb == mock_evt1_callback1);
        fct_chk(b->arg == NULL);
        fct_chk(b->next != NULL);

        b = b->next;
        fct_req(b != NULL);
        fct_chk(b->cb == mock_evt1_callback2);
        fct_chk(b->arg == arg2);
        fct_chk(b->next == NULL);

        jw_event_unbind(evt1, mock_evt1_callback1);
        jw_event_unbind(evt1, mock_evt1_callback2);
    } FCT_TEST_END()
    FCT_TEST_BGN(jw_event_trigger_simple)
    {
        jw_event    *evt1;
        jw_err      err;
        logitem_t   *item;

        evt1 = jw_event_dispatcher_get_event(g_dispatcher, "mockEvent1");

        fct_req(jw_event_bind(evt1, mock_evt1_callback1, NULL, &err) == true);
        fct_req(jw_event_trigger(evt1, NULL, NULL, NULL, &err) == true);

        fct_chk_eq_int(g_audit.count, 1);
        item = g_audit.items;
        fct_chk_eq_str(item->message, log_event_message("mock_evt1_callback1",
                                                        evt1,
                                                        NULL,
                                                        NULL));

        jw_event_unbind(evt1, mock_evt1_callback1);
    } FCT_TEST_END()

    FCT_TEST_BGN(jw_event_trigger_simple_results)
    {
        jw_event    *evt1;
        jw_err      err;
        logitem_t   *item;

        evt1 = jw_event_dispatcher_get_event(g_dispatcher, "mockEvent1");

        fct_req(jw_event_bind(evt1, mock_evt1_callback_handled1, NULL, &err) == true);
        fct_req(jw_event_trigger(evt1, NULL, mock_evt1_result1, NULL, &err) == true);

        fct_chk_eq_int(g_audit.count, 2);
        item = g_audit.items;
        fct_chk_eq_str(item->message, log_event_message("mock_evt1_callback_handled1",
                                                        evt1,
                                                        NULL,
                                                        NULL));
        item = item->next;
        fct_chk_eq_str(item->message, log_result_message("mock_evt1_result1",
                                                         evt1,
                                                         NULL,
                                                         true,
                                                         NULL));

        jw_event_unbind(evt1, mock_evt1_callback_handled1);
    } FCT_TEST_END()
    FCT_TEST_BGN(jw_event_create_errors)
    {
        jw_event    *evt1, *evt2;
        jw_err      err;
        jw_event_dispatcher *dispatch;
        void                *source = "The source";

        fct_chk(jw_event_dispatcher_create(source, NULL, &dispatch, &err));
        fct_chk(!jw_event_dispatcher_create_event(dispatch, "", &evt1, NULL));
        fct_chk(jw_event_dispatcher_create_event(dispatch,
                                                 "",
                                                 &evt1,
                                                 &err) == false);
        fct_chk_eq_int(err.code, JW_ERR_INVALID_ARG);

        fct_req(jw_event_dispatcher_create_event(dispatch,
                                                 "eventOne",
                                                 &evt1,
                                                 &err) == true);
        evt1 = jw_event_dispatcher_get_event(g_dispatcher, "eventOne");

        fct_chk(!jw_event_dispatcher_create_event(dispatch,
                                                  "eventOne",
                                                  &evt2,
                                                  NULL));
        fct_chk(jw_event_dispatcher_create_event(dispatch,
                                                 "eventOne",
                                                 &evt2,
                                                 &err) == false);
        fct_chk_eq_int(err.code, JW_ERR_INVALID_STATE);

        jw_event_dispatcher_destroy(dispatch);
    } FCT_TEST_END()
    FCT_TEST_BGN(jw_event_trigger_nested)
    {
        jw_event    *evt1, *evt2;
        jw_err      err;
        logitem_t   *item;

        fct_req(evt1 = jw_event_dispatcher_get_event(g_dispatcher, "mockEvent1"));
        fct_req(evt2 = jw_event_dispatcher_get_event(g_dispatcher, "mockEvent2"));
        /* bind evt2 to evt1 callbackA so it will  be triggered */
        fct_req(jw_event_bind(evt1, nesting_callbackA, evt2, &err));
        fct_req(jw_event_bind(evt1, nesting_callbackB, NULL, &err));
        fct_req(jw_event_bind(evt2, nesting_callbackB, NULL, &err));
        fct_req(jw_event_bind(evt2, nesting_callbackC, NULL, &err)); /*handled = true */
        /* evt1 callbackA will trigger evt2 with resultB as the result cb.*/
        union
        {
            fn_ptr_wrapper_t *resultBwrapper;
            void             *resultBwrapperPtr;
        } resultBwrapperUnion;
        fct_req(jw_pool_malloc(g_audit.pool, sizeof(fn_ptr_wrapper_t),
                               &resultBwrapperUnion.resultBwrapperPtr, NULL));
        fn_ptr_wrapper_t *resultBwrapper = resultBwrapperUnion.resultBwrapper;
        resultBwrapper->fn = (fn_ptr_t)nesting_resultB;
        fct_chk(jw_event_trigger(evt1, resultBwrapper, nesting_resultA, NULL, &err));

        fct_req(g_audit.count == 6);
        item = g_audit.items;
        /* callbackA logs *after* it triggers evt2. If breath-first is working
           all of evt1 should finish before any of evt2.
           Note that callbackC sets handled to true, and therefore resultB
           will be true*/
        fct_chk_eq_str(item->message, log_event_message("nesting_callbackA",
                                                        evt1,
                                                        resultBwrapper,
                                                        evt2));
        item = item->next;
        fct_chk_eq_str(item->message, log_event_message("nesting_callbackB",
                                                        evt1,
                                                        resultBwrapper,
                                                        NULL));
        item = item->next;
        fct_chk_eq_str(item->message, log_result_message("nesting_resultA",
                                                         evt1,
                                                         resultBwrapper,
                                                         false,
                                                         NULL));
        item = item->next;
        fct_chk_eq_str(item->message, log_event_message("nesting_callbackB",
                                                         evt2,
                                                         NULL,
                                                         NULL));
        item = item->next;
        fct_chk_eq_str(item->message, log_event_message("nesting_callbackC",
                                                         evt2,
                                                         NULL,
                                                         NULL));
        item = item->next;
        fct_chk_eq_str(item->message, log_result_message("nesting_resultB",
                                                         evt2,
                                                         NULL,
                                                         true,
                                                         NULL));

        jw_event_unbind(evt1, nesting_callbackA);
        jw_event_unbind(evt1, nesting_callbackB);
        jw_event_unbind(evt2, nesting_callbackB);
        jw_event_unbind(evt2, nesting_callbackC);
    } FCT_TEST_END()
    FCT_TEST_BGN(jw_event_trigger_double_nested)
    {
        jw_event    *evt1, *evt2;
        jw_err      err;
        logitem_t   *item;

        fct_req(evt1 = jw_event_dispatcher_get_event(g_dispatcher, "mockEvent1"));
        fct_req(evt2 = jw_event_dispatcher_get_event(g_dispatcher, "mockEvent2"));
        // trigger two evt2 events from evt1
        fct_req(jw_event_bind(evt1, double_nesting_callback, evt2, &err));
        fct_req(jw_event_bind(evt2, nesting_callbackB, NULL, &err));

        fct_chk(jw_event_trigger(evt1, NULL, NULL, NULL, &err));

        fct_req(g_audit.count == 3);
        item = g_audit.items;
        fct_chk_eq_str(item->message, log_event_message("double_nesting_callback",
                                                        evt1,
                                                        NULL,
                                                        evt2));
        item = item->next;
        fct_chk_eq_str(item->message, log_event_message("nesting_callbackB",
                                                        evt2,
                                                        NULL,
                                                        NULL));
        item = item->next;
        fct_chk_eq_str(item->message, log_event_message("nesting_callbackB",
                                                        evt2,
                                                        NULL,
                                                        NULL));

        jw_event_unbind(evt1, double_nesting_callback);
        jw_event_unbind(evt2, nesting_callbackB);
    } FCT_TEST_END()
    FCT_TEST_BGN(jw_event_trigger_multi_source)
    {
        jw_event    *evt1, *evt2, *evt3;
        jw_err      err;
        logitem_t   *item;
        jw_event_dispatcher *dispatcher1, *dispatcher2;
        void                *source1 = "the first source";
        void                *source2 = "the second source";
        fct_chk(jw_event_dispatcher_create(source1, NULL, &dispatcher1, &err));
        fct_chk(jw_event_dispatcher_create(source2, NULL, &dispatcher2, &err));
        jw_event_dispatcher_create_event(dispatcher1,
                                         "Event1",
                                         &evt1,
                                         NULL);
        jw_event_dispatcher_create_event(dispatcher2,
                                         "Event2",
                                         &evt2,
                                         NULL);
        jw_event_dispatcher_create_event(dispatcher1,
                                         "Event3",
                                         &evt3,
                                         NULL);
        /* callbackA will fire evt2:callbackC which will fire evt3:callbackB,
           pass events along to these callbacks as bound arguments, simplifies
           trigger logic*/
        fct_req(jw_event_bind(evt1, evt1_callbackA, (void *)evt2, &err) == true);
        fct_req(jw_event_bind(evt3, evt3_callbackB, NULL, &err) == true);
        fct_req(jw_event_bind(evt2, evt2_callbackC, (void *)evt3, &err) == true);
        fct_req(jw_event_bind(evt2, evt2_callbackD, NULL, &err) == true);

        fct_chk(jw_event_trigger(evt1, NULL, NULL,NULL, &err) == true);

        fct_chk_eq_int(g_audit.count, 4);
        item = g_audit.items;
        /* The callbackA for event1 should fire first */
        fct_chk_eq_str(item->message, log_event_message("evt1_callbackA",
                                                        evt1,
                                                        NULL,
                                                        evt2));
        item = item->next;
        /* Both the callbackC and callbackD for event2 should fire next
            because of breadth-first approach*/
        fct_chk_eq_str(item->message, log_event_message("evt2_callbackC",
                                                        evt2,
                                                        NULL,
                                                        evt3));
        item = item->next;
        fct_chk_eq_str(item->message, log_event_message("evt2_callbackD",
                                                        evt2,
                                                        NULL,
                                                        NULL));
        item = item->next;
        /* Finally, the callbackD for event1 fired last */
        fct_chk_eq_str(item->message, log_event_message("evt3_callbackB",
                                                        evt3,
                                                        NULL,
                                                        NULL));

        /* jw_event_dispatcher_destroy unbinds callbacks (if any) when 
           destroying events */
        jw_event_dispatcher_destroy(dispatcher1);
        jw_event_dispatcher_destroy(dispatcher2);
    } FCT_TEST_END()

    /* Concurrent unbind tests
     * Various forms of unbinding from an event during the events trigger
     * execution
     */
    FCT_TEST_BGN(jw_event_trigger_event_unbind)
    {
        jw_event *evt1;
        jw_err err;
        jw_event_binding_t  *b;
        logitem_t *item;

        evt1 = jw_event_dispatcher_get_event(g_dispatcher, "mockEvent1");

        fct_req(jw_event_bind(evt1, mock_evt_unbind_callback1, NULL, &err) == true);
        fct_req(jw_event_bind(evt1, mock_evt1_callback1, NULL, &err) == true);

        fct_req(jw_event_trigger(evt1, NULL, NULL, NULL, &err) == true);

        fct_chk_eq_int(g_audit.count, 2);
        item = g_audit.items;
        fct_chk_eq_str(item->message,
                       log_event_message("mock_evt_unbind_callback1", evt1,
                                         NULL, NULL));
        fct_req(item->next != NULL);
        fct_chk_eq_str(item->next->message,
                       log_event_message("mock_evt1_callback1", evt1,
                                         NULL, NULL));

        b = evt1->bindings;
        fct_req(b != NULL);
        fct_chk(b->cb == mock_evt1_callback1);
        fct_chk(b->next == NULL);

        jw_event_unbind(evt1, mock_evt1_callback1);
        b = evt1->bindings;
        fct_chk(b == NULL);

    } FCT_TEST_END()
    FCT_TEST_BGN(jw_event_trigger_event_multiple_unbind)
    {
        jw_event *evt1;
        jw_err err;
        jw_event_binding_t  *b;
        logitem_t *item;

        evt1 = jw_event_dispatcher_get_event(g_dispatcher, "mockEvent1");

        fct_req(jw_event_bind(evt1, mock_evt_unbind_callback1, NULL, &err) == true);
        fct_req(jw_event_bind(evt1, mock_evt_unbind_callback2, NULL, &err) == true);
        fct_req(jw_event_bind(evt1, mock_evt_unbind_callback3, NULL, &err) == true);
        fct_req(jw_event_bind(evt1, mock_evt_unbind_callback4, NULL, &err) == true);

        fct_req(jw_event_trigger(evt1, NULL, NULL, NULL, &err) == true);

        fct_chk_eq_int(g_audit.count, 4);
        item = g_audit.items;
        fct_chk_eq_str(item->message,
                       log_event_message("mock_evt_unbind_callback1", evt1,
                                         NULL, NULL));
        item = item->next;
        fct_req(item != NULL);
        fct_chk_eq_str(item->message,
                       log_event_message("mock_evt_unbind_callback2", evt1,
                                         NULL, NULL));
        item = item->next;
        fct_req(item != NULL);
        fct_chk_eq_str(item->message,
                       log_event_message("mock_evt_unbind_callback3", evt1,
                                         NULL, NULL));
        item = item->next;
        fct_req(item != NULL);
        fct_chk_eq_str(item->message,
                       log_event_message("mock_evt_unbind_callback4", evt1,
                                         NULL, NULL));

        fct_chk(item->next == NULL);

        b = evt1->bindings;
        fct_req(b == NULL);

    } FCT_TEST_END()
    FCT_TEST_BGN(jw_event_trigger_nested_unbind)
    {
        jw_event    *evt1, *evt2;
        jw_err      err;
        logitem_t   *item;
        jw_event_binding_t  *b;

        fct_req(evt1 = jw_event_dispatcher_get_event(g_dispatcher, "mockEvent1"));
        fct_req(evt2 = jw_event_dispatcher_get_event(g_dispatcher, "mockEvent2"));
        /* bind evt2 to evt1 callbackA so it will  be triggered */
        fct_req(jw_event_bind(evt1, nesting_callbackA, evt2, &err));
        fct_req(jw_event_bind(evt1, nesting_callbackB, NULL, &err));
        fct_req(jw_event_bind(evt2, mock_evt_unbind_callback1, NULL, &err));
        fct_req(jw_event_bind(evt2, nesting_callbackC, NULL, &err)); /*handled = true */
        /* evt1 callbackA will trigger evt2 with resultB as the result cb.*/
        union
        {
            fn_ptr_wrapper_t *resultBwrapper;
            void             *resultBwrapperPtr;
        } resultBwrapperUnion;
        fct_req(jw_pool_malloc(g_audit.pool, sizeof(fn_ptr_wrapper_t),
                               &resultBwrapperUnion.resultBwrapperPtr, NULL));
        fn_ptr_wrapper_t *resultBwrapper = resultBwrapperUnion.resultBwrapper;
        resultBwrapper->fn = (fn_ptr_t)nesting_resultB;
        fct_chk(jw_event_trigger(evt1, resultBwrapper, nesting_resultA, NULL, &err));

        fct_req(g_audit.count == 6);
        item = g_audit.items;
        /* callbackA logs *after* it triggers evt2. If breath-first is working
           all of evt1 should finish before any of evt2.
           Note that callbackC sets handled to true, and therefore resultB
           will be true*/
        fct_chk_eq_str(item->message, log_event_message("nesting_callbackA",
                                                        evt1,
                                                        resultBwrapper,
                                                        evt2));
        item = item->next;
        fct_chk_eq_str(item->message, log_event_message("nesting_callbackB",
                                                        evt1,
                                                        resultBwrapper,
                                                        NULL));
        item = item->next;
        fct_chk_eq_str(item->message, log_result_message("nesting_resultA",
                                                         evt1,
                                                         resultBwrapper,
                                                         false,
                                                         NULL));
        item = item->next;
        fct_chk_eq_str(item->message, log_event_message("mock_evt_unbind_callback1",
                                                         evt2,
                                                         NULL,
                                                         NULL));
        item = item->next;
        fct_chk_eq_str(item->message, log_event_message("nesting_callbackC",
                                                         evt2,
                                                         NULL,
                                                         NULL));
        item = item->next;
        fct_chk_eq_str(item->message, log_result_message("nesting_resultB",
                                                         evt2,
                                                         NULL,
                                                         true,
                                                         NULL));

        jw_event_unbind(evt1, nesting_callbackA);
        jw_event_unbind(evt1, nesting_callbackB);

        b = evt2->bindings;
        fct_req(b != NULL);
        fct_chk(b->cb == nesting_callbackC);
        fct_chk(b->next == NULL);

        jw_event_unbind(evt2, nesting_callbackC);
        b = evt2->bindings;
        fct_chk(b == NULL);

    } FCT_TEST_END()
    FCT_TEST_BGN(jw_event_trigger_event_unbind_middle)
    {
        jw_event *evt1;
        jw_err err;
        jw_event_binding_t  *b;
        logitem_t *item;

        evt1 = jw_event_dispatcher_get_event(g_dispatcher, "mockEvent1");

        fct_req(jw_event_bind(evt1, mock_evt1_callback1, NULL, &err) == true);
        fct_req(jw_event_bind(evt1, mock_evt_unbind_callback1, NULL, &err) == true);
        fct_req(jw_event_bind(evt1, mock_evt1_callback2, NULL, &err) == true);

        fct_req(jw_event_trigger(evt1, NULL, NULL, NULL, &err) == true);

        fct_chk_eq_int(g_audit.count, 3);
        item = g_audit.items;
        fct_chk_eq_str(item->message,
                       log_event_message("mock_evt1_callback1", evt1,
                                         NULL, NULL));
        item = item->next;
        fct_req(item != NULL);
        fct_chk_eq_str(item->message,
                       log_event_message("mock_evt_unbind_callback1", evt1,
                                         NULL, NULL));
        item = item->next;
        fct_req(item != NULL);
        fct_chk_eq_str(item->message,
                       log_event_message("mock_evt1_callback2", evt1,
                                         NULL, NULL));

        fct_chk(item->next == NULL);

        b = evt1->bindings;
        fct_req(b != NULL);
        fct_chk(b->cb == mock_evt1_callback1);
        fct_req(b->next != NULL);

        b = b->next;
        fct_req(b != NULL);
        fct_chk(b->cb == mock_evt1_callback2);
        fct_chk(b->next == NULL);

        jw_event_unbind(evt1, mock_evt1_callback1);
        jw_event_unbind(evt1, mock_evt1_callback2);

        b = evt1->bindings;
        fct_chk(b == NULL);

    } FCT_TEST_END()
    FCT_TEST_BGN(jw_event_trigger_event_unbind_rebind)
    {
        jw_event *evt1;
        jw_err err;
        jw_event_binding_t  *b;
        logitem_t *item;

        evt1 = jw_event_dispatcher_get_event(g_dispatcher, "mockEvent1");

        fct_req(jw_event_bind(evt1, mock_evt1_callback1, NULL, &err) == true);
        fct_req(jw_event_bind(evt1, mock_evt_unbind1_callback1, NULL, &err) == true);
        fct_req(jw_event_bind(evt1, mock_evt_rebind1_callback1, NULL, &err) == true);

        // rebind middle binding -- should not change its order
        fct_req(jw_event_bind(evt1, mock_evt_unbind1_callback1, NULL, &err));

        fct_req(jw_event_trigger(evt1, NULL, NULL, NULL, &err) == true);

        fct_chk_eq_int(g_audit.count, 3);
        item = g_audit.items;
        fct_chk_eq_str(item->message,
                       log_event_message("mock_evt1_callback1", evt1,
                                         NULL, NULL));
        item = item->next;
        fct_req(item != NULL);
        fct_chk_eq_str(item->message,
                       log_event_message("mock_evt_unbind1_callback1", evt1,
                                         NULL, NULL));
        item = item->next;
        fct_req(item != NULL);
        fct_chk_eq_str(item->message,
                       log_event_message("mock_evt_rebind1_callback1", evt1,
                                         NULL, NULL));

        fct_chk(item->next == NULL);

        b = evt1->bindings;
        fct_req(b != NULL);
        fct_chk(b->cb == mock_evt1_callback1);
        fct_chk(b->next != NULL);

        b = b->next;
        fct_req(b != NULL);
        fct_chk(b->cb == mock_evt_unbind1_callback1);
        fct_req(b->next != NULL);

        b = b->next;
        fct_req(b != NULL);
        fct_chk(b->cb == mock_evt_rebind1_callback1);
        fct_chk(b->next == NULL);


        jw_event_unbind(evt1, mock_evt_unbind1_callback1);
        jw_event_unbind(evt1, mock_evt_rebind1_callback1);
        jw_event_unbind(evt1, mock_evt1_callback1);

        b = evt1->bindings;
        fct_chk(b == NULL);

    } FCT_TEST_END()
    FCT_TEST_BGN(jw_event_trigger_event_simple_defer_bind)
    {
        jw_event *evt1;
        jw_err err;
        jw_event_binding_t  *b;
        logitem_t *item;

        evt1 = jw_event_dispatcher_get_event(g_dispatcher, "mockEvent1");

        fct_req(jw_event_bind(evt1, mock_evt_bind1_callback1, NULL, &err) == true);

        fct_req(jw_event_trigger(evt1, NULL, NULL, NULL, &err) == true);

        b = evt1->bindings;
        fct_req(b != NULL);
        fct_chk(b->cb == mock_evt_bind1_callback1);
        fct_chk(b->next != NULL);

        b = b->next;
        fct_req(b != NULL);
        fct_chk(b->cb == mock_evt1_callback1);
        fct_chk(b->next == NULL);

        fct_req(jw_event_trigger(evt1, NULL, NULL, NULL, &err) == true);

        b = evt1->bindings;
        fct_req(b != NULL);
        fct_chk(b->cb == mock_evt_bind1_callback1);
        fct_chk(b->next != NULL);

        b = b->next;
        fct_req(b != NULL);
        fct_chk(b->cb == mock_evt1_callback1);
        fct_chk(b->next == NULL);

        fct_chk_eq_int(g_audit.count, 3);
        item = g_audit.items;
        fct_chk_eq_str(item->message,
                       log_event_message("mock_evt_bind1_callback1", evt1,
                                         NULL, NULL));
        item = item->next;
        fct_chk_eq_str(item->message,
                       log_event_message("mock_evt_bind1_callback1", evt1,
                                         NULL, NULL));
        item = item->next;
        fct_chk_eq_str(item->message,
                       log_event_message("mock_evt1_callback1", evt1,
                                         NULL, NULL));
        fct_chk(item->next == NULL);
    } FCT_TEST_END()
    FCT_TEST_BGN(jw_event_trigger_event_multiple_defer_bind)
    {
        jw_event *evt1;
        jw_err err;
        jw_event_binding_t  *b;
        logitem_t *item;

        evt1 = jw_event_dispatcher_get_event(g_dispatcher, "mockEvent1");

        fct_req(jw_event_bind(evt1, mock_evt_bind1_callback1, NULL, &err) == true);
        fct_req(jw_event_bind(evt1, mock_evt_bind1_callback2, NULL, &err) == true);

        fct_req(jw_event_trigger(evt1, NULL, NULL, NULL, &err) == true);
        fct_req(jw_event_trigger(evt1, NULL, NULL, NULL, &err) == true);

        b = evt1->bindings;
        fct_req(b != NULL);
        fct_chk(b->cb == mock_evt_bind1_callback1);
        fct_chk(b->next != NULL);

        b = b->next;
        fct_req(b != NULL);
        fct_chk(b->cb == mock_evt_bind1_callback2);
        fct_chk(b->next != NULL);

        b = b->next;
        fct_req(b != NULL);
        fct_chk(b->cb == mock_evt1_callback1);
        fct_chk(b->next != NULL);

        b = b->next;
        fct_req(b != NULL);
        fct_chk(b->cb == mock_evt1_callback2);
        fct_chk(b->next == NULL);

        fct_chk_eq_int(g_audit.count, 6);
        item = g_audit.items;
        fct_chk_eq_str(item->message,
                       log_event_message("mock_evt_bind1_callback1", evt1,
                                         NULL, NULL));
        item = item->next;
        fct_chk_eq_str(item->message,
                       log_event_message("mock_evt_bind1_callback2", evt1,
                                         NULL, NULL));
        item = item->next;
        fct_chk_eq_str(item->message,
                       log_event_message("mock_evt_bind1_callback1", evt1,
                                         NULL, NULL));
        item = item->next;
        fct_chk_eq_str(item->message,
                       log_event_message("mock_evt_bind1_callback2", evt1,
                                         NULL, NULL));
        item = item->next;
        fct_chk_eq_str(item->message,
                       log_event_message("mock_evt1_callback1", evt1,
                                         NULL, NULL));
        item = item->next;
        fct_chk_eq_str(item->message,
                       log_event_message("mock_evt1_callback2", evt1,
                                         NULL, NULL));
        fct_chk(item->next == NULL);        
    } FCT_TEST_END()
    FCT_TEST_BGN(jw_event_trigger_event_defer_bind_rebind)
    {
        jw_event *evt1;
        jw_err err;
        jw_event_binding_t  *b;
        logitem_t *item;

        evt1 = jw_event_dispatcher_get_event(g_dispatcher, "mockEvent1");

        fct_req(jw_event_bind(evt1, mock_evt_bind1_callback1, NULL, &err) == true);
        fct_req(jw_event_bind(evt1, mock_evt_rebind1_callback1, NULL, &err) == true);

        fct_req(jw_event_trigger(evt1, NULL, NULL, NULL, &err) == true);
        fct_req(jw_event_trigger(evt1, NULL, NULL, NULL, &err) == true);

        b = evt1->bindings;
        fct_req(b != NULL);
        fct_chk(b->cb == mock_evt_bind1_callback1);
        fct_chk(b->next != NULL);

        b = b->next;
        fct_req(b != NULL);
        fct_chk(b->cb == mock_evt_rebind1_callback1);
        fct_chk(b->next != NULL);

        b = b->next;
        fct_req(b != NULL);
        fct_chk(b->cb == mock_evt1_callback1);
        fct_chk(b->next == NULL);

        fct_chk_eq_int(g_audit.count, 5);
        item = g_audit.items;
        fct_chk_eq_str(item->message,
                       log_event_message("mock_evt_bind1_callback1", evt1,
                                         NULL, NULL));
        item = item->next;
        fct_chk_eq_str(item->message,
                       log_event_message("mock_evt_rebind1_callback1", evt1,
                                         NULL, NULL));
        item = item->next;
        fct_chk_eq_str(item->message,
                       log_event_message("mock_evt_bind1_callback1", evt1,
                                         NULL, NULL));
        item = item->next;
        fct_chk_eq_str(item->message,
                       log_event_message("mock_evt_rebind1_callback1", evt1,
                                         NULL, NULL));
        item = item->next;
        fct_chk_eq_str(item->message,
                       log_event_message("mock_evt1_callback1", evt1,
                                         NULL, NULL));
        fct_chk(item->next == NULL);
    } FCT_TEST_END()
    FCT_TEST_BGN(jw_event_trigger_event_defer_bind_unbind)
    {
        jw_event *evt1;
        jw_err err;
        jw_event_binding_t  *b;
        logitem_t *item;

        evt1 = jw_event_dispatcher_get_event(g_dispatcher, "mockEvent1");

        fct_req(jw_event_bind(evt1, mock_evt_bind1_callback1, NULL, &err) == true);
        fct_req(jw_event_bind(evt1, mock_evt_unbind1_callback1, NULL, &err) == true);

        fct_req(jw_event_trigger(evt1, NULL, NULL, NULL, &err) == true);

        b = evt1->bindings;
        fct_req(b != NULL);
        fct_chk(b->cb == mock_evt_bind1_callback1);
        fct_chk(b->next != NULL);

        b = b->next;
        fct_req(b != NULL);
        fct_chk(b->cb == mock_evt_unbind1_callback1);
        fct_chk(b->next == NULL);

        fct_chk_eq_int(g_audit.count, 2);
        item = g_audit.items;
        fct_chk_eq_str(item->message,
                       log_event_message("mock_evt_bind1_callback1", evt1,
                                         NULL, NULL));
        item = item->next;
        fct_chk_eq_str(item->message,
                       log_event_message("mock_evt_unbind1_callback1", evt1,
                                         NULL, NULL));
        fct_chk(item->next == NULL);
    } FCT_TEST_END()
    FCT_TEST_BGN(jw_event_trigger_event_defer_bind_unbind_rebind)
    {
        jw_event *evt1;
        jw_err err;
        jw_event_binding_t  *b;
        logitem_t *item;

        evt1 = jw_event_dispatcher_get_event(g_dispatcher, "mockEvent1");

        fct_req(jw_event_bind(evt1, mock_evt_bind1_callback1, NULL, &err) == true);
        fct_req(jw_event_bind(evt1, mock_evt_unbind1_callback1, NULL, &err) == true);
        fct_req(jw_event_bind(evt1, mock_evt_rebind1_callback1, NULL, &err) == true);

        fct_req(jw_event_trigger(evt1, NULL, NULL, NULL, &err) == true);
        fct_req(jw_event_trigger(evt1, NULL, NULL, NULL, &err) == true);

        b = evt1->bindings;
        fct_req(b != NULL);
        fct_chk(b->cb == mock_evt_bind1_callback1);
        fct_chk(b->next != NULL);

        b = b->next;
        fct_req(b != NULL);
        fct_chk(b->cb == mock_evt_unbind1_callback1);
        fct_chk(b->next != NULL);

        b = b->next;
        fct_req(b != NULL);
        fct_chk(b->cb == mock_evt_rebind1_callback1);
        fct_chk(b->next != NULL);

        b = b->next;
        fct_req(b != NULL);
        fct_chk(b->cb == mock_evt1_callback1);
        fct_chk(b->next == NULL);

        fct_chk_eq_int(g_audit.count, 7);
        item = g_audit.items;
        fct_chk_eq_str(item->message,
                       log_event_message("mock_evt_bind1_callback1", evt1,
                                         NULL, NULL));
        item = item->next;
        fct_chk_eq_str(item->message,
                       log_event_message("mock_evt_unbind1_callback1", evt1,
                                          NULL, NULL));
        item = item->next;
        fct_chk_eq_str(item->message,
                       log_event_message("mock_evt_rebind1_callback1", evt1,
                                         NULL, NULL));
        item = item->next;
        fct_chk_eq_str(item->message,
                       log_event_message("mock_evt_bind1_callback1", evt1,
                                         NULL, NULL));
        item = item->next;
        fct_chk_eq_str(item->message,
                       log_event_message("mock_evt_unbind1_callback1", evt1,
                                         NULL, NULL));
        item = item->next;
        fct_chk_eq_str(item->message,
                       log_event_message("mock_evt_rebind1_callback1", evt1,
                                         NULL, NULL));
        item = item->next;
        fct_chk_eq_str(item->message,
                       log_event_message("mock_evt1_callback1", evt1,
                                         NULL, NULL));
        fct_chk(item->next == NULL);
    } FCT_TEST_END()
    FCT_TEST_BGN(jw_event_trigger_prepared)
    {
        jw_event_trigger_data *trigger_data;
        jw_event *evt;

        // can't use audit trail since that would require memory allocation
        evt = jw_event_dispatcher_get_event(g_dispatcher, "mockEvent1");
        fct_req(jw_event_bind(evt, mock_nofail_callback, NULL, NULL));
        
        fct_req(jw_event_prepare_trigger(g_dispatcher, &trigger_data, NULL));

        g_oom_malloc_called = false;
        g_nofail_callback_called = false;
        jw_data_set_memory_funcs(mock_oom_malloc, mock_oom_realloc, NULL);

        jw_event_trigger_prepared(evt, NULL, NULL, NULL, trigger_data);

        jw_data_set_memory_funcs(NULL, NULL, NULL);
        fct_chk(!g_oom_malloc_called);
        fct_chk(g_nofail_callback_called);

        jw_event_unbind(evt, mock_evt1_callback_handled1);
    } FCT_TEST_END()
    FCT_TEST_BGN(jw_event_trigger_prepare_unprepare)
    {
        jw_event_trigger_data *trigger_data;

        jw_data_set_memory_funcs(_counting_malloc, _counting_realloc, _counting_free);

        fct_req(jw_event_prepare_trigger(g_dispatcher, &trigger_data, NULL));
        jw_event_unprepare_trigger(trigger_data);

        fct_chk_eq_int(_mallocCnt, _freeCnt);
        
        jw_data_set_memory_funcs(NULL, NULL, NULL);
    } FCT_TEST_END()
    FCT_TEST_BGN(jw_event_trigger_deferred_destroy)
    {
        jw_event            *evt        = NULL;
        jw_event_dispatcher *dispatcher = NULL;

        g_destroy_first_free = false;
        g_destroy_first_alloc = NULL;
        jw_data_set_memory_funcs(destroy_test_malloc, NULL, destroy_test_free);
        fct_req(jw_event_dispatcher_create(g_source, NULL, &dispatcher, NULL));
        fct_req(jw_event_dispatcher_create_event(dispatcher,
                                                 "destroyEvt", &evt, NULL));
        fct_req(jw_event_bind(evt, destroying_callback, dispatcher, NULL));
        fct_chk(jw_event_trigger(evt, evt, NULL, NULL, NULL));

        // can't use audit trail since the evt is destroyed during the callback
        fct_chk(g_destroy_first_alloc);
        fct_chk(g_destroy_correctly_deferred);
    
        jw_data_set_memory_funcs(NULL, NULL, NULL);
    } FCT_TEST_END()
    FCT_TEST_BGN(jw_event_trigger_deferred_destroy_async)
    {
        struct event_base  *evbase;
        jw_htable           *config;
        jw_workq            *workq;
        jw_event_dispatcher *dispatcher = NULL;
        jw_event            *evt        = NULL;

        evbase = event_base_new();
        fct_req(evbase);

        fct_req(jw_htable_create(0, jw_strcase_hashcode, jw_strcase_compare,
                                 &config, NULL));
        fct_req(jw_htable_put(config, JW_WORKQ_CONFIG_SELECTOR,
                              evbase, NULL, NULL));
        fct_req(jw_workq_create(config, &workq, NULL));

        g_destroy_first_free = false;
        g_destroy_first_alloc = NULL;
        jw_data_set_memory_funcs(destroy_test_malloc, NULL, destroy_test_free);
        fct_req(jw_event_dispatcher_create(g_source, workq, &dispatcher, NULL));
        fct_req(jw_event_dispatcher_create_event(dispatcher,
                                                 "destroyEvt", &evt, NULL));
        fct_req(jw_event_bind(evt, destroying_callback, dispatcher, NULL));
        fct_chk(jw_event_trigger(evt, evt, NULL, NULL, NULL));

        event_base_dispatch(evbase);

        // can't use audit trail since the evt is destroyed during the callback
        fct_chk(g_destroy_first_alloc);
        fct_chk(g_destroy_correctly_deferred);

        jw_data_set_memory_funcs(NULL, NULL, NULL);

        jw_workq_destroy(workq);
        jw_htable_destroy(config);
        event_base_free(evbase);
    } FCT_TEST_END()
    FCT_TEST_BGN(jw_event_oom)
    {
        struct event_base  *evbase = NULL;
        jw_htable           *config = NULL;
        jw_workq            *workq  = NULL;
        jw_event_dispatcher *dispatcher;
        jw_event            *evt;

        // runs through twice, once for sync and once for async
        while (true)
        {
            // create dispatcher
            OOM_SIMPLE_TEST(jw_event_dispatcher_create(
                                    g_source, workq, &dispatcher, &err));
            OOM_TEST_INIT();
            OOM_TEST(NULL, jw_event_dispatcher_create(
                                    g_source, workq, &dispatcher, NULL));

            fct_chk(jw_event_dispatcher_get_workq(dispatcher) == workq);

            // create event (use two events: an event cannot be created twice)
            jw_err err;
            OOM_RECORD_ALLOCS(jw_event_dispatcher_create_event(
                                    dispatcher, "ev", &evt, &err));
            OOM_TEST_INIT();
            OOM_TEST_CONDITIONAL_CHECK(&err,
                                       jw_event_dispatcher_create_event(
                                            dispatcher, "ev2", &evt, &err),
                                       true);
            OOM_TEST_INIT();
            OOM_TEST(NULL, jw_event_dispatcher_create_event(
                                    dispatcher, "ev2", &evt, NULL));

            // bind event (use two callbacks: rebinding changes the code path)
            OOM_RECORD_ALLOCS(jw_event_bind(
                                        evt, async_callback, dispatcher, &err));
            OOM_TEST_INIT();
            OOM_TEST_CONDITIONAL_CHECK(&err,
                                       jw_event_bind(evt, destroying_callback,
                                                     dispatcher, &err),
                                       true);
            OOM_TEST_INIT();
            OOM_TEST(NULL, jw_event_bind(evt, destroying_callback,
                                         dispatcher, NULL));

            // trigger event
            uint32_t call_count = 0;
            OOM_SIMPLE_TEST(jw_event_trigger(
                                        evt, &call_count, NULL, NULL, &err));
            OOM_TEST_INIT();
            OOM_TEST(NULL, jw_event_trigger(
                                        evt, &call_count, NULL, NULL, NULL));

            if (evbase)
            {
                event_base_dispatch(evbase);
            }
            
            if (workq)
            {
                break;
            }
            
            // prepare for async run
            jw_event_dispatcher_destroy(dispatcher);
            
            evbase = event_base_new();
            fct_req(evbase);

            fct_req(jw_htable_create(0, jw_strcase_hashcode, jw_strcase_compare,
                                     &config, NULL));
            fct_req(jw_htable_put(config, JW_WORKQ_CONFIG_SELECTOR,
                                  evbase, NULL, NULL));
            fct_req(jw_workq_create(config, &workq, NULL));
        }

        jw_event_dispatcher_destroy(dispatcher);
        jw_workq_destroy(workq);
        jw_htable_destroy(config);
        event_base_free(evbase);
    } FCT_TEST_END()
    FCT_TEST_BGN(jw_event_async)
    {
        struct event_base  *evbase;
        jw_htable           *config;
        jw_workq            *workq;
        jw_event_dispatcher *dispatcher;
        jw_event            *evt;

        evbase = event_base_new();
        fct_req(evbase);

        fct_req(jw_htable_create(0, jw_strcase_hashcode, jw_strcase_compare,
                                 &config, NULL));
        fct_req(jw_htable_put(config, JW_STREAM_CONFIG_SELECTOR,
                              (void *)evbase, NULL, NULL));
        fct_req(jw_workq_create(config, &workq, NULL));

        fct_req(jw_event_dispatcher_create(g_source, workq, &dispatcher, NULL));
        fct_req(jw_event_dispatcher_create_event(dispatcher, "ev", &evt, NULL));
        fct_req(jw_event_bind(evt, async_callback, dispatcher, NULL));

        uint32_t call_count = 0;
        fct_chk(jw_event_trigger(evt, &call_count, NULL, NULL, NULL));

        // ensure the event handlers are called asynchronously
        fct_chk_eq_int(0, call_count);
        event_base_dispatch(evbase);
        fct_chk_eq_int(1, call_count);

        jw_event_dispatcher_destroy(dispatcher);
        jw_workq_destroy(workq);
        jw_htable_destroy(config);
        event_base_free(evbase);
    } FCT_TEST_END()
} FCTMF_FIXTURE_SUITE_END()
