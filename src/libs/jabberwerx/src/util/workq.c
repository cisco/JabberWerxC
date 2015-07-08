/**
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

#define __STDC_FORMAT_MACROS // for PRIu64 and friends
#include <inttypes.h>
#include <assert.h>
#include <string.h>
#include <stdint.h>

#include <event2/event.h>
#include <event2/bufferevent.h>

#include <jabberwerx/util/log.h>
#include <jabberwerx/util/workq.h>
#include <jabberwerx/util/mem.h>
#include <jabberwerx/stream.h>

#define MS_PER_SECOND 1000
#define US_PER_MS     1000

#define PUSH_ITEM_NDC int _ndcDepth = _push_address_ndc((void*)(item), __func__, "workq_item")
#define PUSH_Q_NDC int _ndcDepth = _push_address_ndc((void*)(q), __func__, "workq")
#define POP_NDC jw_log_pop_ndc(_ndcDepth)
static int _push_address_ndc(void *item, const char *entrypoint, const char *ndc_label)
{
    assert(item);
    assert(entrypoint);

    return jw_log_push_ndc("%s=%p; entrypoint=%s", ndc_label, (void *)item, entrypoint);
}

/**
 * Information specific to a delay in workq item scheduling
 */
typedef struct jw_workq_delay_t
{
    // time in milliseconds to delay
    uint64_t        time;
    // event tracking the delay. The event used as a delay timer is lazily
    //    created when the item sets a delay.
    // The event will exist until the item is destroyed.
    struct event   *event;
    // should the item be prepended after delay?
    bool            prepend;
} _jw_workq_delay;

/**
 * jw_workq contains both a scheduled queue and a list of all items
 * created referencing the workq.
 *
 * The schedule queued is implemented using jw_workq->head, jw_workq->tail and
 * jw_workq->size. The queue is implemented in the item using the
 * jw_workq_item->next.
 *
 * The list of all items created is implemented using jw_workq->items and
 * jw_workq->itemCount. The list is implemented as a doubly linked list using
 * jw_workq_item->prev_item and jw_workq_item->next_item.
 */
typedef struct jw_workq_item_t
{
    jw_workq      *q;
    //Data passed to jw_workq_func
    void         *data;
    //Function executed when item is dequeued
    jw_workq_func func;
    //a cleaner callback fired when data is replaced or item destroyed
    jw_workq_item_cleaner cleaner;
    //Is this item scheduled?
    bool          scheduled;
    // delay information
    _jw_workq_delay delay;
    //Previously (closer to head) scheduled item
    jw_workq_item *prev;
    //Next scheduled item
    jw_workq_item *next;
    //Previous item in list of all items
    jw_workq_item *prev_item;
    //Next item in the list of all items
    jw_workq_item *next_item;
} _jw_workq_item;

typedef struct jw_workq_t
{
    //Head of scheduled queue
    jw_workq_item *head;
    //The tail of the scheduled queue
    jw_workq_item *tail;
    //delayed list
    jw_workq_item *delayed;

    //The number of items in the scheduled queue
    size_t        size;
    //List of all items referencing this queue
    jw_workq_item *items;
    //Ref count on pause/resume calls
    size_t        pr_ref_count;

    struct event_base *base;
    //Event used to process scheduled items
    struct event      *process_event;
} _jw_workq;


/**
 * A few state checkers to make code easier to read
 */
static inline bool _should_delay(jw_workq_item *item)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    return 0 != jw_workq_item_get_delay(item);
}
//all scheduled items will have this flag set
static inline bool _is_scheduled(jw_workq_item *item)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;
    assert(NULL != item);

    return item->scheduled;
}
//Delayed items have a pending timer event.
//todo log tv_out
static inline bool _is_delayed(jw_workq_item *item)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    return  _is_scheduled(item) &&
            NULL != item->delay.event &&
            //true if pending or active.
            0 != event_pending(item->delay.event, EV_TIMEOUT, NULL);
}
static inline bool _is_enqueued(jw_workq_item *item)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    return _is_scheduled(item) && !_is_delayed(item);
}

/**
 * Add the given item to the given queue. prepend spcifies a prepend or append.
 */
static void _enqueue(jw_workq *q,
                     jw_workq_item *item,
                     bool prepend)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    item->prev = item->next = NULL;
    if (NULL == q->head) //if !head then !tail
    {
        q->head = q->tail = item;
    }
    else if (0 != prepend)
    {
        item->next = q->head;
        q->head->prev = item;
        q->head = item;
    }
    else
    {
        q->tail->next = item;
        item->prev = q->tail;
        q->tail = item;
    }
    item->scheduled = true;
    ++q->size;
}

/**
 * Remove and return the top item in the scheduled queue
 */
static jw_workq_item *_dequeue(jw_workq *q)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(NULL != q);
    assert(NULL != q->head);

    jw_workq_item *item = q->head;
    if (q->tail == q->head) //one item in q
    {
        q->tail = q->head = NULL;
    }
    else
    {
        q->head = item->next;
        q->head->prev = NULL;
    }
    item->prev = item->next = NULL;
    item->scheduled = false;
    --q->size;
    return item;
}

/**
 * activate our processing event
 */
static void _tickle_q(jw_workq *q)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(NULL != q);

    // don't event if paused or empty
    if (0 == q->pr_ref_count && 0 < q->size)
    {
        event_active(q->process_event, EV_TIMEOUT, 0);
    }
}

/**
 * enqueue an item that was delayed
 */
static void _schedule_item_cb(evutil_socket_t sock, short what, void *arg)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    UNUSED_PARAM(sock);
    UNUSED_PARAM(what);

    jw_workq_item   *item = arg;

    _enqueue(item->q, item, item->delay.prepend);
    _tickle_q(item->q);
}

/**
 * schedule enqueuing an item to be delayed
 */
static void _schedule_item(jw_workq_item *item, bool prepend)
{
    JW_LOG_TRACE_FUNCTION("delay=%"PRIu64, item->delay.time);

    assert(NULL != item->delay.event);

    // schedule in the future
    struct timeval tv = {
        item->delay.time / MS_PER_SECOND,
        (item->delay.time % MS_PER_SECOND) * US_PER_MS
    };

    item->scheduled = true;
    item->delay.prepend = prepend;
    evtimer_add(item->delay.event, &tv);
}

static bool _enqueue_item(jw_workq_item *item,
                          bool    prepend,
                          jw_err *err)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(NULL != item);

    if (_is_scheduled(item))
    {
        JABBERWERX_ERROR(err, JW_ERR_INVALID_STATE);
        return false;
    }

    if (_should_delay(item))
    {
        _schedule_item(item, prepend);
    }
    else
    {
        _enqueue(item->q, item, prepend);
    }
    _tickle_q(item->q);
    return true;
}

/**
 * Cancel an item by removing it from the scheduled queue as needed
 */
static void _cancel_item(jw_workq *q, jw_workq_item *item)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    //cancel delay (if any)
    if (_is_delayed(item))
    {
        evtimer_del(item->delay.event);
    }
    else if (_is_enqueued(item))
    {
        if (NULL != item->prev)
        {
            item->prev->next = item->next;
        }
        else
        {
            q->head = item->next;
        }

        if (NULL != item->next)
        {
            item->next->prev = item->prev;
        }
        else
        {
            q->tail = item->prev;
        }

        --q->size;
        item->next = item->prev = NULL;
    }
    item->scheduled = false;

    if (0 == q->size && q->process_event)
    {
        jw_log(JW_LOG_DEBUG, "queue now empty; canceling processing event");
        event_del(q->process_event);
    }
}

/**
 * Remove the given item from the workq's list of all items.
 * Items are removed by their destructors.
 */
static void _remove_item(jw_workq *q, jw_workq_item *item)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(NULL != item);
    assert(NULL != q->items); //destroying item, therefore item *is* in items list

    if (NULL != item->prev_item)
    {
        item->prev_item->next_item = item->next_item;
    }
    else
    {
        q->items = item->next_item;
    }
    if (NULL != item->next_item)
    {
        item->next_item->prev_item = item->prev_item;
    }
    item->next_item = item->prev_item = NULL;
}

JABBERWERX_API bool jw_workq_item_create(jw_workq *q,
                                         jw_workq_func fn,
                                         jw_workq_item **item,
                                         jw_err *err)
{
    PUSH_ITEM_NDC;
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(NULL != q);
    assert(NULL != fn);
    assert(NULL != item);

    jw_workq_item *ret = jw_data_malloc(sizeof(struct jw_workq_item_t));
    if (NULL == ret)
    {
        POP_NDC;
        JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
        return false;
    }
    memset(ret, 0, sizeof(struct jw_workq_item_t));
    ret->func = fn;
    ret->q = q;

    //cleanup items on queue destruction
    if (NULL != q->items)
    {
        q->items->prev_item = ret;
    }
    ret->next_item = q->items;
    q->items = ret;
    ret->prev_item = NULL;

    *item = ret;
    POP_NDC;

    return true;
}

JABBERWERX_API void jw_workq_item_destroy(jw_workq_item *item)
{
    PUSH_ITEM_NDC;
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(NULL != item);

    jw_workq *q = item->q;
    _cancel_item(q, item);//"dequeues" the item, cancels delay timers
    _remove_item(q, item);//removes from list of all items

    if (NULL != item->delay.event)
    {
        event_free(item->delay.event);
        item->delay.event = NULL;
    }
    if (NULL != item->cleaner)
    {
        item->cleaner(item, item->data);
    }
    jw_data_free(item);
    POP_NDC;
}

JABBERWERX_API void jw_workq_item_set_data(jw_workq_item *item,
                                           void *data,
                                           jw_workq_item_cleaner cleaner)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(NULL != item);

    if (NULL != item->cleaner)
    {
        item->cleaner(item, item->data);
    }
    item->data = data;
    item->cleaner = cleaner;
}

JABBERWERX_API void jw_workq_item_cancel(jw_workq_item *item)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(NULL != item);

    _cancel_item(item->q, item);
}

JABBERWERX_API bool jw_workq_item_append(jw_workq_item *item,
                                         jw_err *err)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    return _enqueue_item(item, false, err);
}

JABBERWERX_API bool jw_workq_item_prepend(jw_workq_item *item,
                                          jw_err *err)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    return _enqueue_item(item, true, err);
}

JABBERWERX_API uint64_t jw_workq_item_get_delay(jw_workq_item *item)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(NULL != item);

    return item->delay.time;
}

JABBERWERX_API bool jw_workq_item_set_delay(jw_workq_item *item,
                                            uint64_t delay,
                                            jw_err *err)
{
    PUSH_ITEM_NDC;

    assert(NULL != item);

    if (!item->delay.event && 0 < delay)
    {
        // want a delay; no delay previously set
        item->delay.event = evtimer_new(item->q->base,
                                        _schedule_item_cb,
                                        item);
        if (NULL == item->delay.event)
        {
            //assume it's a memory allocation error
            JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
            POP_NDC;
            return false;
        }
    }
    item->delay.time = delay;
    POP_NDC;
    return true;
}

JABBERWERX_API jw_workq *jw_workq_item_get_workq(jw_workq_item *item)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(NULL != item);

    return item->q;
}

JABBERWERX_API void *jw_workq_item_get_data(jw_workq_item *item)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(NULL != item);

    return item->data;
}

JABBERWERX_API bool jw_workq_item_is_scheduled(jw_workq_item *item)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(NULL != item);

    return item->scheduled;
}

JABBERWERX_API void jw_workq_item_free_data_cleaner(jw_workq_item *item,
                                                    void *data)
{
    UNUSED_PARAM(item);
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    jw_data_free(data);
}

JABBERWERX_API void jw_workq_item_pool_cleaner(jw_workq_item *item, void *data)
{
    UNUSED_PARAM(item);
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    jw_pool_destroy((jw_pool*)data);
}

/**
 * work queue process function, fired as callback of buffer event
 */
static void _jw_workq_process(evutil_socket_t signum, short what, void *arg)
{
    UNUSED_PARAM(signum);
    UNUSED_PARAM(what);

    jw_workq *q = (jw_workq*)arg;

    PUSH_Q_NDC;
    JW_LOG_TRACE_FUNCTION_NO_ARGS;
    jw_workq_item *item = _dequeue(q);

    item->func(item, item->data);
    _tickle_q(q);
    POP_NDC;
}

JABBERWERX_API bool jw_workq_create(jw_htable *config,
                                    jw_workq **q,
                                    jw_err *err)
{
    jw_workq *newq;

    PUSH_Q_NDC;
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(NULL != q);

    newq = (jw_workq*)jw_data_malloc(sizeof(_jw_workq));
    if (NULL == newq)
    {
        JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
        POP_NDC;
        return false;
    }
    memset(newq, 0, sizeof(_jw_workq));

    if (NULL != config)
    {
        newq->base =
           (struct event_base *)jw_htable_get(config,
                                              JW_WORKQ_CONFIG_SELECTOR);
    }
    if (NULL == newq->base)
    {
        JABBERWERX_ERROR(err, JW_ERR_INVALID_ARG);
        jw_workq_destroy(newq);
        POP_NDC;
        return false;
    }
    newq->process_event = evtimer_new(newq->base, _jw_workq_process, newq);
    if (NULL == newq->process_event)
    {
        JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
        jw_workq_destroy(newq);
        POP_NDC;
        return false;
    }

    *q = newq;
    POP_NDC;
    return true;
}

JABBERWERX_API void jw_workq_destroy(jw_workq *q)
{
    PUSH_Q_NDC;
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(q != NULL);
    //stop eventing asap
    if (NULL != q->process_event)
    {
        event_free(q->process_event);
        q->process_event = NULL;
    }

    //walk all items and destroy each in turn
    while(NULL != q->items)
    {
        jw_workq_item_destroy(q->items);
    }
    jw_data_free(q);
    POP_NDC;
}

JABBERWERX_API void jw_workq_pause(jw_workq *q)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(q != NULL);

    q->pr_ref_count++;
    event_del(q->process_event);
}

JABBERWERX_API void jw_workq_resume(jw_workq *q)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(q != NULL);

    if (q->pr_ref_count > 0)
    {
        q->pr_ref_count--;
    }

    _tickle_q(q);
}

JABBERWERX_API size_t jw_workq_get_length(jw_workq *q)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(q != NULL);
    return q->size;
}

JABBERWERX_API bool jw_workq_is_empty(jw_workq *q)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(q != NULL);

    if (0 == q->size)
    {
        jw_workq_item *itr = q->delayed;
        while (NULL != itr)
        {
            return false;
            itr = itr->next;
        }
    }
    return 0 == q->size;
}

JABBERWERX_API struct event_base *jw_workq_get_selector(jw_workq *q)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(q != NULL);
    return q->base;
}

/* vim: set sw=4: */
