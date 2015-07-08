/**
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

#include "fct.h"
#include "test_utils.h" //OOM macros
#include <jabberwerx/util/log.h>
#include <jabberwerx/util/htable.h>
#include <jabberwerx/util/workq.h>
#include <jabberwerx/util/mem.h>
#include <event2/event.h>


static jw_htable *_new_queue_config(struct event_base *base)
{
    jw_htable *ret;
    jw_htable_create(7,
                     jw_strcase_hashcode,
                     jw_strcase_compare,
                     &ret, NULL);
    if (base)
    {
        jw_htable_put(ret, JW_WORKQ_CONFIG_SELECTOR, (void *)base, NULL, NULL);
    }
    return ret;
}


//kind of ugly but meh.
typedef struct test_func_arg_t
{
    jw_workq  *q;
    const char *label;
    jw_workq_func next_func;
    void *data;
} *test_func_arg;

static test_func_arg _new_arg(jw_workq *q,
                             const char* label,
                             jw_workq_func func,
                             void *data)
{
    test_func_arg arg = jw_data_malloc(sizeof(struct test_func_arg_t));
    arg->q = q;
    arg->label = label;
    arg->next_func = func;
    arg->data = data;
    return arg;
}

static size_t _cleaner_count = 0;
static void _count_cleaner(jw_workq_item *item, void *data)
{
    UNUSED_PARAM(item);
    ++_cleaner_count;
    jw_data_free(data);
}
static void _noop_cb(jw_workq_item *item, void *data)
{
    UNUSED_PARAM(item);
    UNUSED_PARAM(data);
}
static void _timed_cb(jw_workq_item *item, void *data)
{
    UNUSED_PARAM(item);

    struct timeval *tv = data;
    gettimeofday(tv, NULL);
}

//test callbacks that concat function info onto actual_results
static void _results(jw_workq_item *item, void *data)
{
    UNUSED_PARAM(item);

    const char *label = ((test_func_arg)data)->label;
    char *res = (char *)((test_func_arg)data)->data;
    strcat(strcat(res, "r"), label);
}

static jw_workq_item *_new_cb_item(jw_workq_item *item,
                                  void *data,
                                  const char*push_str)
{
    jw_workq_item *retItem;

    jw_workq_item_create(jw_workq_item_get_workq(item),
                         ((test_func_arg)data)->next_func,
                         &retItem,
                         NULL);
    const char *label = ((test_func_arg)data)->label;
    char *res = ((test_func_arg)data)->data;
    strcat(strcat(res, push_str), label);

    ((test_func_arg)data)->next_func = _results; //stop indirection
    jw_workq_item_set_data(retItem, data, NULL);
    return retItem;
}

//_append_cb and _prepend_cb also allow a second function to be pushed onto
//the queue. After the indirection _results is called to terminate.
static void _append_cb(jw_workq_item *item, void *data)
{
    jw_workq_item *thisItem = _new_cb_item(item, data, "a");
    jw_workq_item_append(thisItem, NULL);
}

static void _prepend_cb(jw_workq_item *item, void *data)
{
    jw_workq_item *thisItem = _new_cb_item(item, data, "p");
    jw_workq_item_prepend(thisItem, NULL);
}

//pause the given queue
static void _pause_cb(jw_workq_item *item, void *data)
{
    UNUSED_PARAM(item);
    const char *label = ((test_func_arg)data)->label;
    char *res = ((test_func_arg)data)->data;
    strcat(strcat(strcat(res, "<paused "), label), ">");
    jw_workq_pause(jw_workq_item_get_workq(item));
}

static jw_loglevel _initlevel;
FCTMF_FIXTURE_SUITE_BGN(workq_test)
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

    FCT_TEST_BGN(jw_workq_create)
    {
        struct event_base *test_base;
        jw_htable *qconfig;
        jw_workq *q;
        jw_err  err;

        test_base = event_base_new();

        //no config
        qconfig = NULL;
        fct_req(false == jw_workq_create(qconfig, &q, &err));
        fct_chk(err.code == JW_ERR_INVALID_ARG);

        //no base
        fct_req(false == jw_workq_create(qconfig, &q, &err));
        fct_chk(err.code == JW_ERR_INVALID_ARG);
        fct_req(false == jw_workq_create(qconfig, &q, NULL));

        //test good create
        qconfig = _new_queue_config(test_base);
        fct_req(jw_workq_create(qconfig, &q, &err));
        fct_chk(jw_workq_get_length(q) == 0);
        fct_chk(jw_workq_get_selector(q) == test_base);
        jw_workq_destroy(q);

        //no mem create
        OOM_SIMPLE_TEST(jw_workq_create(qconfig, &q, &err));
        jw_workq_destroy(q);

        //test with NULL jw_err. Previous OOM_SIMPLE_TEST has already
        //initialized OOM, OOM_TEST may be called without OOM_RECORD_ALLOCS
        OOM_TEST_INIT();
        OOM_TEST(NULL, jw_workq_create(qconfig, &q, NULL));

        jw_htable_destroy(qconfig);
        event_base_free(test_base);
    }FCT_TEST_END()

    FCT_TEST_BGN(jw_workq_item_create)
    {
        struct event_base *test_base;
        jw_htable *qconfig;
        jw_workq *q;
        jw_workq_item *item, *item2;
        jw_err  err;

        test_base = event_base_new();

        //create a queue item
        qconfig = _new_queue_config(test_base);
        fct_req(jw_workq_create(qconfig, &q, &err));
        fct_chk(jw_workq_get_length(q) == 0);
        fct_chk(jw_workq_get_selector(q) == test_base);

        //create an item
        fct_req(jw_workq_item_create(q, _noop_cb, &item, &err));
        fct_chk(jw_workq_item_get_workq(item) == q);
        jw_workq_item_destroy(item);

        //test multiple unscheduled items destruction
        fct_req(jw_workq_item_create(q, _noop_cb, &item2, &err));
        jw_workq_item_set_data(item2, NULL, _count_cleaner);
        fct_req(jw_workq_item_create(q, _noop_cb, &item, &err));
        jw_workq_item_set_data(item, NULL, _count_cleaner);
        fct_req(jw_workq_item_create(q, _noop_cb, &item, &err));
        jw_workq_item_set_data(item, NULL, _count_cleaner);
        fct_req(jw_workq_item_create(q, _noop_cb, &item, &err));
        jw_workq_item_set_data(item, NULL, _count_cleaner);
        fct_chk(jw_workq_get_length(q) == 0);
        //test removing item from interior of unscheduled list
        jw_workq_item_destroy(item2);
        fct_chk(_cleaner_count == 1);
        //test removing unscheduled items on queue destruction
        jw_workq_destroy(q);
        fct_chk(_cleaner_count == 4);

        //no mem create an item
        fct_req(jw_workq_create(qconfig, &q, &err));
        OOM_SIMPLE_TEST(jw_workq_item_create(q, _noop_cb, &item, &err));
        jw_workq_item_destroy(item);

        //test with NULL jw_err. Previous OOM_SIMPLE_TEST has already
        //initialized OOM, OOM_TEST may be called without OOM_RECORD_ALLOCS
        OOM_TEST_INIT();
        OOM_TEST(NULL, jw_workq_item_create(q, _noop_cb, &item, NULL));

        jw_workq_destroy(q);
        jw_htable_destroy(qconfig);
        event_base_free(test_base);
    }FCT_TEST_END()

    FCT_TEST_BGN(jw_workq_item_delay)
    {
        //jw_log_set_level(JW_LOG_DEBUG);

        struct event_base *test_base;
        jw_htable *qconfig;
        jw_workq *q;
        jw_workq_item *item;
        jw_err err;
        struct timeval called;
        test_func_arg arg;
        char actual_results[1024];
        memset(actual_results, 0, 1024);

        test_base = event_base_new();
        qconfig = _new_queue_config(test_base);
        fct_req(jw_workq_create(qconfig, &q, &err));
        fct_req(jw_workq_item_create(q, _timed_cb, &item, &err));
        fct_chk(NULL == jw_workq_item_get_data(item));

        fct_chk(0 == jw_workq_item_get_delay(item));
        fct_chk(jw_workq_item_set_delay(item, 5222, &err));
        fct_chk(5222 == jw_workq_item_get_delay(item));

        fct_chk(jw_workq_item_set_delay(item, 0, &err));
        fct_chk(0 == jw_workq_item_get_delay(item));

        fct_chk(jw_workq_item_set_delay(item, 12676, &err));
        fct_chk(12676 == jw_workq_item_get_delay(item));

        // check to see if it gets called ...
        memset(&called, 0, sizeof(struct timeval));
        jw_workq_item_set_data(item, &called, NULL);
        fct_req(jw_workq_item_set_delay(item, 1000, &err));

        struct timeval maxtime = {5, 0};
        struct timeval start;
        struct timeval end;

        fct_req(jw_workq_item_prepend(item, &err));

        // record start
        gettimeofday(&start, NULL);
        //bail after maxtime (5 seconds)
        event_base_loopexit(test_base, &maxtime);
        //kick everything off
        event_base_dispatch(test_base);

        // record end
        gettimeofday(&end, NULL);

        // start checks ...
        fct_chk(0 != called.tv_sec);

        // compare times ...
        fct_chk_eq_int((end.tv_sec - start.tv_sec), 5);
        fct_chk_eq_int((called.tv_sec - start.tv_sec), 1);

        //fresh new queue
        jw_workq_destroy(q);
        fct_req(jw_workq_create(qconfig, &q, &err));
        fct_req(jw_workq_item_create(q, _timed_cb, &item, &err));

        //create a number of items that should fire in delay order, mix in a
        //few immediately queued items to make sure they fire first.
        fct_chk_eq_int(jw_workq_get_length(q), 0);
        fct_chk(jw_workq_is_empty(q));

        //rstatic-1
        fct_req(jw_workq_item_create(q, _results, &item, &err));
        arg = _new_arg(q, "static-1", NULL, actual_results);
        jw_workq_item_set_data(item, arg, jw_workq_item_free_data_cleaner);
        fct_req(jw_workq_item_append(item, &err));
        fct_chk_eq_int(jw_workq_get_length(q), 1);
        fct_chk(!jw_workq_is_empty(q));
        //2 second timer
        fct_req(jw_workq_item_create(q, _results, &item, &err));
        arg = _new_arg(q, "2", NULL, actual_results);
        jw_workq_item_set_data(item, arg, jw_workq_item_free_data_cleaner);
        fct_chk(jw_workq_item_set_delay(item, 2000, &err));
        fct_req(jw_workq_item_append(item, &err));
        fct_chk_eq_int(jw_workq_get_length(q), 1);
        //rstatic-3rstatic-1
        fct_req(jw_workq_item_create(q, _results, &item, &err));
        arg = _new_arg(q, "static-3", NULL, actual_results);
        jw_workq_item_set_data(item, arg, jw_workq_item_free_data_cleaner);
        fct_chk(jw_workq_item_set_delay(item, 0, &err));
        fct_req(jw_workq_item_prepend(item, &err));
        fct_chk(jw_workq_item_set_delay(item, 3000, &err));
        fct_chk_eq_int(jw_workq_get_length(q), 2);
        //three seond delay
        fct_req(jw_workq_item_create(q, _results, &item, &err));
        arg = _new_arg(q, "3", NULL, actual_results);
        jw_workq_item_set_data(item, arg, jw_workq_item_free_data_cleaner);
        fct_chk(jw_workq_item_set_delay(item, 3000, &err));
        fct_req(jw_workq_item_append(item, &err));
        fct_chk_eq_int(jw_workq_get_length(q), 2);
        //five second delay
        fct_req(jw_workq_item_create(q, _results, &item, &err));
        arg = _new_arg(q, "5", NULL, actual_results);
        jw_workq_item_set_data(item, arg, jw_workq_item_free_data_cleaner);
        fct_chk(jw_workq_item_set_delay(item, 5000, &err));
        fct_req(jw_workq_item_append(item, &err));
        fct_chk_eq_int(jw_workq_get_length(q), 2);
        //rstatic-3rstatic-1rstatic-2
        fct_req(jw_workq_item_create(q, _results, &item, &err));
        arg = _new_arg(q, "static-2", NULL, actual_results);
        jw_workq_item_set_data(item, arg, jw_workq_item_free_data_cleaner);
        fct_req(jw_workq_item_append(item, &err));
        fct_chk_eq_int(jw_workq_get_length(q), 3);
        //first one second timer
        fct_req(jw_workq_item_create(q, _results, &item, &err));
        arg = _new_arg(q, "1.0", NULL, actual_results);
        jw_workq_item_set_data(item, arg, jw_workq_item_free_data_cleaner);
        fct_chk(jw_workq_item_set_delay(item, 1000, &err));
        fct_req(jw_workq_item_append(item, &err));
        fct_chk_eq_int(jw_workq_get_length(q), 3);
        //four second delay
        fct_req(jw_workq_item_create(q, _results, &item, &err));
        arg = _new_arg(q, "4", NULL, actual_results);
        jw_workq_item_set_data(item, arg, jw_workq_item_free_data_cleaner);
        fct_chk(jw_workq_item_set_delay(item, 4000, &err));
        fct_req(jw_workq_item_append(item, &err));
        fct_chk_eq_int(jw_workq_get_length(q), 3);
        //another one second delay should still be fired after the one above
        fct_req(jw_workq_item_create(q, _results, &item, &err));
        arg = _new_arg(q, "1.1", NULL, actual_results);
        jw_workq_item_set_data(item, arg, jw_workq_item_free_data_cleaner);
        fct_chk(jw_workq_item_set_delay(item, 1000, &err));
        fct_req(jw_workq_item_append(item, &err));
        fct_chk_eq_int(jw_workq_get_length(q), 3);

        //bail after maxtime (6 seconds)
        maxtime.tv_sec = 6;
        event_base_loopexit(test_base, &maxtime);
        //kick everything off
        event_base_dispatch(test_base);

        fct_chk_eq_str((char *)actual_results, "rstatic-3rstatic-1rstatic-2r1.0r1.1r2r3r4r5");

        //test q destruction when items are still delayed
        fct_req(jw_workq_item_create(q, _noop_cb, &item, &err));
        fct_chk(jw_workq_item_set_delay(item, 10000, &err));
        fct_req(jw_workq_item_append(item, &err));
        jw_workq_item_destroy(item);

        maxtime.tv_sec = 1;
        event_base_loopexit(test_base, &maxtime);
        //kick everything off
        event_base_dispatch(test_base);
        //test attempting to immediately schedule a delayed job

        jw_workq_destroy(q);
        jw_htable_destroy(qconfig);
        event_base_free(test_base);
    }FCT_TEST_END()

    FCT_TEST_BGN(jw_workq_item_data)
    {
        struct event_base *test_base;
        jw_htable *qconfig;
        jw_workq *q;
        jw_workq_item *item;
        jw_err  err;
        void *data;

        test_base = event_base_new();
        qconfig = _new_queue_config(test_base);
        fct_req(jw_workq_create(qconfig, &q, &err));
        fct_req(jw_workq_item_create(q, _noop_cb, &item, &err));
        fct_chk(NULL == jw_workq_item_get_data(item));

        _cleaner_count = 0;
        jw_workq_item_set_data(item, jw_data_malloc(1), _count_cleaner);
        fct_chk(0 == _cleaner_count);
        jw_workq_item_set_data(item, jw_data_malloc(1), _count_cleaner);
        fct_chk(1 == _cleaner_count);
        jw_workq_item_destroy(item);
        fct_chk(2 == _cleaner_count);

        fct_req(jw_workq_item_create(q, _noop_cb, &item, &err));
        _cleaner_count = 0;
        data = jw_data_malloc(1);
        jw_workq_item_set_data(item, data, _count_cleaner);
        fct_chk(0 == _cleaner_count);
        fct_chk(data == jw_workq_item_get_data(item));
        data = jw_data_malloc(1);
        jw_workq_item_set_data(item, data, _count_cleaner);
        fct_chk(1 == _cleaner_count);
        fct_chk(data == jw_workq_item_get_data(item));
        //items should be destroyed on q destruction
        jw_workq_destroy(q);
        fct_chk(2 == _cleaner_count);

        jw_htable_destroy(qconfig);
        event_base_free(test_base);
    }FCT_TEST_END()

    FCT_TEST_BGN(jw_workq_queue_manipulation)
    {
        struct event_base *test_base;
        jw_htable *qconfig;
        jw_workq_item *item, *item2, *item3;
        jw_workq *q;
        jw_err  err;

        test_base = event_base_new();
        qconfig = _new_queue_config(test_base);
        fct_req(jw_workq_create(qconfig, &q, &err));

        fct_req(jw_workq_item_create(q, _noop_cb, &item, &err));
        fct_req(jw_workq_item_create(q, _noop_cb, &item2, &err));
        fct_req(jw_workq_item_create(q, _noop_cb, &item3, &err));
        jw_workq_item_set_data(item, NULL, _count_cleaner);
        jw_workq_item_set_data(item2, NULL, _count_cleaner);
        jw_workq_item_set_data(item3, NULL, _count_cleaner);
        fct_chk(0 == jw_workq_get_length(q));

        //unscheduled list manipulation
        _cleaner_count = 0;
        //test remove unscheduled from head
        jw_workq_item_destroy(item3);
        fct_chk(1 == _cleaner_count);
        //test remove unscheduled from tail
        fct_req(jw_workq_item_create(q, _noop_cb, &item3, &err));
        jw_workq_item_set_data(item3, NULL, _count_cleaner);
        jw_workq_item_destroy(item);
        fct_chk(2 == _cleaner_count);
        //test remove unscheduled from interior
        fct_req(jw_workq_item_create(q, _noop_cb, &item, &err));
        jw_workq_item_set_data(item, NULL, _count_cleaner);
        jw_workq_item_destroy(item3);
        fct_chk(3 == _cleaner_count);
        //test remove unscheduled on destruction
        jw_workq_destroy(q);
        fct_chk(5 == _cleaner_count);

        //scheduled queue manipulation
        fct_req(jw_workq_create(qconfig, &q, &err));

        fct_req(jw_workq_item_create(q, _noop_cb, &item, &err));
        fct_req(jw_workq_item_create(q, _noop_cb, &item2, &err));
        fct_req(jw_workq_item_create(q, _noop_cb, &item3, &err));
        jw_workq_item_set_data(item, NULL, _count_cleaner);
        jw_workq_item_set_data(item2, NULL, _count_cleaner);
        jw_workq_item_set_data(item3, NULL, _count_cleaner);
        fct_chk(0 == jw_workq_get_length(q));

        fct_chk(jw_workq_item_prepend(item, &err));
        fct_chk(1 == jw_workq_get_length(q));
        fct_chk(jw_workq_item_is_scheduled(item));

        //invalid to append/prepend already scheduled item
        fct_chk(false == jw_workq_item_append(item, &err));
        fct_chk(err.code == JW_ERR_INVALID_STATE);
        fct_chk(false == jw_workq_item_prepend(item, &err));
        fct_chk(err.code == JW_ERR_INVALID_STATE);
        //repeat with NULL jw_err for coverage
        fct_chk(false == jw_workq_item_append(item, NULL));
        fct_chk(false == jw_workq_item_prepend(item, NULL));

        fct_chk(!jw_workq_item_is_scheduled(item2));
        fct_chk(jw_workq_item_append(item2, &err));
        fct_chk(jw_workq_item_is_scheduled(item2));
        fct_chk(2 == jw_workq_get_length(q));
        fct_chk(false == jw_workq_item_append(item2, &err));
        fct_chk(err.code == JW_ERR_INVALID_STATE);
        fct_chk(false == jw_workq_item_prepend(item2, &err));
        fct_chk(err.code == JW_ERR_INVALID_STATE);

        fct_chk(!jw_workq_item_is_scheduled(item3));
        fct_chk(jw_workq_item_append(item3, &err));
        fct_chk(jw_workq_item_is_scheduled(item3));
        fct_chk(3 == jw_workq_get_length(q));
        fct_chk(false == jw_workq_item_prepend(item3, &err));
        fct_chk(err.code == JW_ERR_INVALID_STATE);
        fct_chk(false == jw_workq_item_append(item3, &err));
        fct_chk(err.code == JW_ERR_INVALID_STATE);

        //remove item from head of scheduled queue
        _cleaner_count = 0;
        jw_workq_item_destroy(item);
        fct_chk(2 == jw_workq_get_length(q));
        fct_chk(1 == _cleaner_count);
        //remove item from tail of scheduled queue
        fct_req(jw_workq_item_create(q, _noop_cb, &item, &err));
        jw_workq_item_set_data(item, NULL, _count_cleaner);
        fct_chk(jw_workq_item_append(item, &err));
        jw_workq_item_destroy(item);
        fct_chk(2 == _cleaner_count);
        //remove item from head of scheduled queue
        fct_req(jw_workq_item_create(q, _noop_cb, &item, &err));
        jw_workq_item_set_data(item, NULL, _count_cleaner);
        fct_chk(jw_workq_item_prepend(item, &err));
        jw_workq_item_destroy(item2); //2 is middle item
        fct_chk(3 == _cleaner_count);
        fct_chk(2 == jw_workq_get_length(q));
        //remove scheduled remaining 2 items when q is destroyed
        jw_workq_destroy(q);
        fct_chk(5 == _cleaner_count);
        event_base_free(test_base);
        jw_htable_destroy(qconfig);
    }FCT_TEST_END()

    FCT_TEST_BGN(jw_workq_item_cancel)
    {
        struct event_base *test_base;
        jw_htable *qconfig;
        jw_workq_item *item, *item2;
        jw_workq *q;
        jw_err  err;
        jw_pool *pool;

        test_base = event_base_new();
        qconfig = _new_queue_config(test_base);
        fct_req(jw_workq_create(qconfig, &q, &err));

        fct_req(jw_workq_item_create(q, _noop_cb, &item, &err));
        fct_req(jw_workq_item_create(q, _noop_cb, &item2, &err));
        jw_workq_item_set_data(item, NULL, _count_cleaner);
        jw_workq_item_set_data(item2, NULL, _count_cleaner);

        jw_workq_item_cancel(item); //cancel non-scheduled item - noop
        jw_workq_item_append(item, &err);
        jw_workq_item_append(item2, &err);
        fct_chk(2 == jw_workq_get_length(q));
        jw_workq_item_cancel(item);
        fct_chk(1 == jw_workq_get_length(q));
        jw_workq_item_cancel(item2);
        fct_chk(0 == jw_workq_get_length(q));

        //pool cleaner
        fct_req(jw_pool_create(1024, &pool, &err));
        fct_req(jw_workq_item_create(q, _noop_cb, &item, &err));
        jw_workq_item_set_data(item, pool, jw_workq_item_pool_cleaner);
        fct_chk(jw_workq_item_append(item, &err));
        fct_chk(1 == jw_workq_get_length(q));
        jw_workq_item_cancel(item);
        fct_chk(0 == jw_workq_get_length(q));

        jw_workq_destroy(q);
        jw_htable_destroy(qconfig);
        event_base_free(test_base);
    }FCT_TEST_END()

    FCT_TEST_BGN(jw_workq_item_process)
    {
        struct event_base *test_base;
        jw_htable *qconfig;
        jw_workq_item *item;
        jw_workq *q;
        jw_err  err;
        test_func_arg arg;

        char actual_results[1024];

        memset(actual_results, 0, 1024);

        test_base = event_base_new();
        qconfig = _new_queue_config(test_base);
        fct_req(jw_workq_create(qconfig, &q, &err));

        //<>
        arg = _new_arg(q, "0", NULL, actual_results);
        fct_chk(jw_workq_item_create(q, _results, &item, NULL));
        jw_workq_item_set_data(item, arg, jw_workq_item_free_data_cleaner);
        fct_chk(jw_workq_item_prepend(item, NULL));
        //<r0>
        arg = _new_arg(q, "1", NULL, actual_results);
        fct_chk(jw_workq_item_create(q, _results, &item, NULL));
        jw_workq_item_set_data(item, arg, jw_workq_item_free_data_cleaner);
        fct_chk(jw_workq_item_prepend(item, NULL));
        //<r0r1>
        arg = _new_arg(q, "2", NULL, actual_results);
        fct_chk(jw_workq_item_create(q, _results, &item, NULL));
        jw_workq_item_set_data(item, arg, jw_workq_item_free_data_cleaner);
        fct_chk(jw_workq_item_prepend(item, NULL));
        //<r0r1r2>
        arg = _new_arg(q, "3", _append_cb, actual_results);
        fct_chk(jw_workq_item_create(q, _prepend_cb, &item, NULL));
        jw_workq_item_set_data(item, arg, jw_workq_item_free_data_cleaner);
        fct_chk(jw_workq_item_prepend(item, NULL));
        //<r0r1r2p3[a3[r3]]a4[p4[r4]]>
        //[] indicate additonal operations, p3[a3[r3]] means
        //prepend an [append operation which will append a [result operation]]
        arg = _new_arg(q, "4", _prepend_cb, actual_results);
        fct_chk(jw_workq_item_create(q, _append_cb, &item, NULL));
        jw_workq_item_set_data(item, arg, jw_workq_item_free_data_cleaner);
        fct_chk(jw_workq_item_prepend(item, NULL));
        fct_chk(5 == jw_workq_get_length(q));
        //execution should be
        //<r0r1r2p3[a3[r3]]> a4[p4[r4]] - out stack = <a4>
        //<p4[r4]r0r1r2p3[a3[r3]]>
        //<p4[r4]r0r1r2> p3[a3[r3]] os = <a4p3>
        //<p4[r4]r0r1r2a3[r3]>
        //<p4[r4]r0r1r2> a3[r3] os = <a4p3a3>
        //<r3p4[r4]r0r1r2>
        //<r3p4[r4]r0r1> r2 os = <a4p3a3r2>
        //<r3p4[r4]r0> r1 os = <a4p3a3r2r1>
        //<r3p4[r4]> r0 os = <a4p3a3r2r1r0>
        //<r3> p4[r4]
        //<r3r4> os = <a4p3a3r2r1r0p4>
        //<r3> r4 os = <a4p3a3r2r1r0p4r4>
        //<> r3 os = <a4p3a3r2r1r0p4r4r3>
        event_base_dispatch(jw_workq_get_selector(q));
        fct_chk(0 == jw_workq_get_length(q));
        //a == _append_cb, p == _prepend_cb, r == _results
        fct_chk(0 == strcmp((char *)actual_results, "a4p3a3r2r1r0p4r4r3"));

        //append
        memset(actual_results, 0, 1024);
        arg = _new_arg(q, "0", NULL, actual_results);
        fct_chk(jw_workq_item_create(q, _results, &item, NULL));
        jw_workq_item_set_data(item, arg, jw_workq_item_free_data_cleaner);
        fct_chk(jw_workq_item_append(item, NULL));
        //<r0>
        arg = _new_arg(q, "1", NULL, actual_results);
        fct_chk(jw_workq_item_create(q, _results, &item, NULL));
        jw_workq_item_set_data(item, arg, jw_workq_item_free_data_cleaner);
        fct_chk(jw_workq_item_append(item, NULL));
        //<r0r1>
        arg = _new_arg(q, "2", NULL, actual_results);
        fct_chk(jw_workq_item_create(q, _results, &item, NULL));
        jw_workq_item_set_data(item, arg, jw_workq_item_free_data_cleaner);
        fct_chk(jw_workq_item_append(item, NULL));
        //<r0r1r2>
        arg = _new_arg(q, "3", _append_cb, actual_results);
        fct_chk(jw_workq_item_create(q, _prepend_cb, &item, NULL));
        jw_workq_item_set_data(item, arg, jw_workq_item_free_data_cleaner);
        fct_chk(jw_workq_item_append(item, NULL));

        arg = _new_arg(q, "4", _prepend_cb, actual_results);
        fct_chk(jw_workq_item_create(q, _append_cb, &item, NULL));
        jw_workq_item_set_data(item, arg, jw_workq_item_free_data_cleaner);
        fct_chk(jw_workq_item_append(item, NULL));

        fct_chk(5 == jw_workq_get_length(q));
        //r0-r1-r2-p3(pushes a3(appends r3))-a4(appends p4(pushes r4))
        //pop r0 - pop r1 - pop r2 - pop p3 - push a3 pop a3 append r3 pop a4
        //   append p4 pop r3 pop p4 push r4 pop r4
        // pop order: r0r1r2p3a3a4r3p4r4
        event_base_dispatch(jw_workq_get_selector(q));
        fct_chk(0 == jw_workq_get_length(q));
        fct_chk(0 == strcmp((char *)actual_results, "r0r1r2p3a3a4r3p4r4"));

        //mix appends and prepends
        memset(actual_results, 0, 1024);

        arg = _new_arg(q, "0", NULL, actual_results);
        fct_chk(jw_workq_item_create(q, _results, &item, NULL));
        jw_workq_item_set_data(item, arg, jw_workq_item_free_data_cleaner);
        fct_chk(jw_workq_item_append(item, NULL));
        //<r0>
        arg = _new_arg(q, "1", _prepend_cb, actual_results);
        fct_chk(jw_workq_item_create(q, _append_cb, &item, NULL));
        jw_workq_item_set_data(item, arg, jw_workq_item_free_data_cleaner);
        fct_chk(jw_workq_item_append(item, NULL));
        //<r0r1>
        arg = _new_arg(q, "2", _append_cb, actual_results);
        fct_chk(jw_workq_item_create(q, _prepend_cb, &item, NULL));
        jw_workq_item_set_data(item, arg, jw_workq_item_free_data_cleaner);
        fct_chk(jw_workq_item_prepend(item, NULL));
        //<r0r1r2>
        arg = _new_arg(q, "3", _append_cb, actual_results);
        fct_chk(jw_workq_item_create(q, _append_cb, &item, NULL));
        jw_workq_item_set_data(item, arg, jw_workq_item_free_data_cleaner);
        fct_chk(jw_workq_item_append(item, NULL));

        arg = _new_arg(q, "4", _append_cb, actual_results);
        fct_chk(jw_workq_item_create(q, _prepend_cb, &item, NULL));
        jw_workq_item_set_data(item, arg, jw_workq_item_free_data_cleaner);
        fct_chk(jw_workq_item_prepend(item, NULL));

        fct_chk(5 == jw_workq_get_length(q));
        //p4(push a4(append r4))- p2(append a2(append r2))- r0 -
        //    a1(append p1(push r1))-a3(append a3(append r3))
        //pop p4 - push a4 - pop a4 - append r4 - pop p2 - push a2 - pop a2 -
        //    append r2 - pop r0 - pop a1 - append p1 - pop a3 - append a3 -
        //    pop r4 - pop r2 - pop p1 - push r1 - pop r1 - pop a3 -
        //    append r3 - pop r3
        // pop order: p4a4p2a2r0a1a3r4r2p1r1a3r3
        event_base_dispatch(jw_workq_get_selector(q));
        fct_chk(0 == jw_workq_get_length(q));
        fct_chk(0 == strcmp((char *)actual_results, "p4a4p2a2r0a1a3r4r2p1r1a3r3"));

        jw_workq_destroy(q);
        jw_htable_destroy(qconfig);
        event_base_free(test_base);
    }FCT_TEST_END()

    FCT_TEST_BGN(jw_workq_pause_resume)
    {
        struct event_base *test_base;
        jw_htable *qconfig;
        jw_workq_item *item;
        jw_workq *q;
        jw_err  err;
        test_func_arg arg;

        char actual_results[1024];

        memset(actual_results, 0, 1024);

        test_base = event_base_new();
        qconfig = _new_queue_config(test_base);
        fct_req(jw_workq_create(qconfig, &q, &err));

        //puase_cb will stop processing and allow base dispatch to complete
        arg = _new_arg(q, "0", NULL, actual_results);
        fct_chk(jw_workq_item_create(q, _results, &item, NULL));
        jw_workq_item_set_data(item, arg, jw_workq_item_free_data_cleaner);
        fct_chk(jw_workq_item_prepend(item, NULL));
        //<r0>
        arg = _new_arg(q, "1", NULL, actual_results);
        fct_chk(jw_workq_item_create(q, _results, &item, NULL));
        jw_workq_item_set_data(item, arg, jw_workq_item_free_data_cleaner);
        fct_chk(jw_workq_item_prepend(item, NULL));
        //<r0r1>
        arg = _new_arg(q, "2", NULL, actual_results);
        fct_chk(jw_workq_item_create(q, _results, &item, NULL));
        jw_workq_item_set_data(item, arg, jw_workq_item_free_data_cleaner);
        fct_chk(jw_workq_item_prepend(item, NULL));
        //<r0r1r2>
        arg = _new_arg(q, "3", NULL, actual_results);
        fct_chk(jw_workq_item_create(q, _pause_cb, &item, NULL));
        jw_workq_item_set_data(item, arg, jw_workq_item_free_data_cleaner);
        fct_chk(jw_workq_item_prepend(item, NULL));

        arg = _new_arg(q, "4", NULL, actual_results);
        fct_chk(jw_workq_item_create(q, _results, &item, NULL));
        jw_workq_item_set_data(item, arg, jw_workq_item_free_data_cleaner);
        fct_chk(jw_workq_item_prepend(item, NULL));

        fct_chk(5 == jw_workq_get_length(q));

        event_base_dispatch(jw_workq_get_selector(q));
        fct_chk(3 == jw_workq_get_length(q));
        fct_chk(0 == strcmp((char *)actual_results, "r4<paused 3>"));
        //dispatch while still paused, noop
        event_base_dispatch(jw_workq_get_selector(q));
        fct_chk(3 == jw_workq_get_length(q));
        fct_chk(0 == strcmp((char *)actual_results, "r4<paused 3>"));

        //nothing should change until dispatch
        jw_workq_resume(q);
        fct_chk(3 == jw_workq_get_length(q));
        fct_chk(0 == strcmp((char *)actual_results, "r4<paused 3>"));
        event_base_dispatch(jw_workq_get_selector(q));
        fct_chk(0 == jw_workq_get_length(q));
        fct_chk(0 == strcmp((char *)actual_results, "r4<paused 3>r2r1r0"));

        //test ref counts
        memset(actual_results, 0, 1024);

        arg = _new_arg(q, "0", NULL, actual_results);
        fct_chk(jw_workq_item_create(q, _results, &item, NULL));
        jw_workq_item_set_data(item, arg, jw_workq_item_free_data_cleaner);
        fct_chk(jw_workq_item_prepend(item, NULL));
        //<r0>
        // pause *after* adding something to catch
        //  "process event pending when paused" code. Event will never be added
        //  when paused
        jw_workq_pause(q);
        arg = _new_arg(q, "1", NULL, actual_results);
        fct_chk(jw_workq_item_create(q, _results, &item, NULL));
        jw_workq_item_set_data(item, arg, jw_workq_item_free_data_cleaner);
        fct_chk(jw_workq_item_prepend(item, NULL));
        //<r0r1>
        arg = _new_arg(q, "2", NULL, actual_results);
        fct_chk(jw_workq_item_create(q, _results, &item, NULL));
        jw_workq_item_set_data(item, arg, jw_workq_item_free_data_cleaner);
        fct_chk(jw_workq_item_prepend(item, NULL));
        //<r0r1r2>
        arg = _new_arg(q, "3", NULL, actual_results);
        fct_chk(jw_workq_item_create(q, _results, &item, NULL));
        jw_workq_item_set_data(item, arg, jw_workq_item_free_data_cleaner);
        fct_chk(jw_workq_item_prepend(item, NULL));

        arg = _new_arg(q, "4", NULL, actual_results);
        fct_chk(jw_workq_item_create(q, _results, &item, NULL));
        jw_workq_item_set_data(item, arg, jw_workq_item_free_data_cleaner);
        fct_chk(jw_workq_item_prepend(item, NULL));

        fct_chk(5 == jw_workq_get_length(q));
        //paused, nothing should happen
        event_base_dispatch(jw_workq_get_selector(q));
        fct_chk(5 == jw_workq_get_length(q));
        fct_chk(0 == strlen((char *)actual_results));
        jw_workq_pause(q); //inc ref count
        jw_workq_resume(q);
        //paused, nothing should happen
        event_base_dispatch(jw_workq_get_selector(q));
        fct_chk(5 == jw_workq_get_length(q));
        fct_chk(0 == strlen((char *)actual_results));
        jw_workq_resume(q);
        jw_workq_resume(q); //one too many resumes
        jw_workq_pause(q); //but this should still pause
        event_base_dispatch(jw_workq_get_selector(q));
        fct_chk(5 == jw_workq_get_length(q));
        fct_chk(0 == strlen((char *)actual_results));
        //should run this time
        jw_workq_resume(q);
        event_base_dispatch(jw_workq_get_selector(q));
        fct_chk(0 == jw_workq_get_length(q));
        fct_chk(0 == strcmp((char *)actual_results, "r4r3r2r1r0"));

        jw_workq_destroy(q);
        jw_htable_destroy(qconfig);
        event_base_free(test_base);
    }FCT_TEST_END()
} FCTMF_FIXTURE_SUITE_END()

/* vim: set sw=4: */
