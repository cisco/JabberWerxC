/**
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

#include "jabberwerx/eventing.h"
#include "jabberwerx/util/htable.h"
#include "jabberwerx/util/str.h"
#include "jabberwerx/util/log.h"

#include <assert.h>
#include <string.h>

#include "include/eventing_int.h"

/* Internal Constants */
static const int DISPATCH_BUCKETS = 7;
static const size_t MOMENT_POOLSIZE = 0;

/**
 * Event triggering data.
 */
typedef struct _jw_event_trigger_t
{
    jw_event_moment_t *moment;
    jw_pool            *pool;
} jw_event_trigger_t;


#define PUSH_EVENTING_NDC int _ndcDepth = _push_eventing_ndc(dispatch, __func__)
#define POP_EVENTING_NDC jw_log_pop_ndc(_ndcDepth)
static int _push_eventing_ndc(jw_event_dispatcher *dispatch,
                              const char *entrypoint)
{
    assert(entrypoint);

    return jw_log_push_ndc("eventing dispatcher=%p; entrypoint=%s",
                           (void *)dispatch, entrypoint);
}

/* Internal Functions */
/**
 * Searched the notifier for an existing binding of the given callback.
 * This function updates {pmatch} and {pins} as appropriate, including
 * setting values to NULL if there is no match.
 *
 * returns whether the binding was found
 */
static inline bool _remove_binding(jw_event_notifier_t *notifier,
                                   jw_event_notify_callback cb,
                                   jw_event_binding_t **pmatch,
                                   jw_event_binding_t **pins)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    jw_event_binding_t *curr = notifier->bindings;
    jw_event_binding_t *prev = NULL;
    bool head = true;

    /* initialize to not found */
    *pmatch = NULL;
    while (curr != NULL)
    {
        if (curr->cb == cb)
        {
            // callback matches; remove from list
            if (head)
            {
                notifier->bindings = curr->next;
            }
            else
            {
                prev->next = curr->next;
            }

            /* remember found binding */
            *pmatch = curr;

            /* finish breaking the list */
            curr->next = NULL;

            break;
        }

        head = false;
        prev = curr;
        curr = curr->next;
    }

    /* update insert point */
    if (pins)
    {
        *pins = prev;
    }

    return (*pmatch != NULL);
}

static inline void _process_pending_unbinds(jw_event *event)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    jw_event_binding_t *prev = NULL;
    jw_event_binding_t *cur  = event->bindings;

    while (cur != NULL)
    {
        jw_event_binding_t *remove = cur;
        if (!cur->unbound)
        {
            prev = cur;
            remove = NULL;
        }
        else
        {
            if (prev != NULL)
            {
                prev->next = cur->next;
            }
            else
            {
                event->bindings = cur->next;
            }
        }

        cur = cur->next;

        jw_data_free(remove);
    }
}

static inline void _set_bind_status(jw_event *event)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    jw_event_binding_t *cur = event->bindings;
    while (cur != NULL)
    {
        cur->normal_bound = true;
        cur = cur->next;
    }
}

static void _moment_destroy(jw_event_moment_t *moment)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(moment);
    
    if (NULL != moment->workq_item)
    {
        jw_workq_item_destroy(moment->workq_item);
    }
    
    jw_pool_destroy(moment->evt.pool);
}

static void _handle_trigger_int(jw_event_dispatcher *dispatch)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    jw_event_moment_t *moment = dispatch->next_moment;
    assert(moment);
    jw_event_data      evt    = &moment->evt;
    
    jw_log(JW_LOG_DEBUG, "processing event '%s'", evt->name);

    assert(NULL == dispatch->running);
    dispatch->running = evt->notifier;
    _set_bind_status(evt->notifier);

    // process callbacks
    for (jw_event_binding_t *binding = moment->bindings;
         NULL != binding;
         binding = binding->next)
    {
        if (binding->normal_bound)
        {
            bool handled = evt->handled;

            binding->cb(evt, binding->arg);
            
            // prevent callbacks from "unhandling"
            evt->handled = handled || evt->handled;
        }
    }

    // report event results
    if (moment->result_cb)
    {
        moment->result_cb(evt, evt->handled, moment->result_arg);
    }

    // clean up and prepare for next moment
    _process_pending_unbinds(evt->notifier);
    dispatch->next_moment = moment->next;
    _moment_destroy(moment);

    if (NULL == dispatch->next_moment)
    {
        dispatch->moment_queue_tail = NULL;
    }
    dispatch->running = NULL;

    // only destroy here if we're asynchronous -- the synchronous code destroys
    // the dispatcher outside of the queue handling loop
    if (dispatch->destroy_pending && dispatch->workq)
    {
        jw_event_dispatcher_destroy(dispatch);
    }
}

static void _handle_trigger(jw_workq_item *item, void *data)
{
    UNUSED_PARAM(item);

    jw_event_dispatcher *dispatch = data;

    PUSH_EVENTING_NDC;
    JW_LOG_TRACE_FUNCTION_NO_ARGS;
    _handle_trigger_int(dispatch);
    POP_EVENTING_NDC;
}

/**
 * Enqueues an event and, if this dispatcher is synchronous and is not currently
 * handling an event, processes it immediately.  If this dispatcher is async,
 * processing is scheduled.
 */
static inline void _dispatch_trigger(jw_event_dispatcher *dispatcher,
                                     jw_event_moment_t  *moment)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    if (NULL != dispatcher->moment_queue_tail)
    {
        dispatcher->moment_queue_tail->next = moment;
    }
    if (NULL == dispatcher->next_moment)
    {
        dispatcher->next_moment = moment;
    }
    dispatcher->moment_queue_tail = moment;

    if (NULL != dispatcher->workq)
    {
        jw_err err;
        if (!jw_workq_item_append(moment->workq_item, &err))
        {
            jw_log_err(JW_LOG_ERROR, &err, "unable to append event workq item");
            assert(false);
        }

        // trigger is handled asynchronously
        return;
    }

    if (dispatcher->running != NULL)
    {
        jw_log(JW_LOG_DEBUG, "already processing events; deferring event '%s'",
               moment->evt.name);
        return;
    }

    // handle queued triggers synchronously
    while (NULL != dispatcher->next_moment && !dispatcher->destroy_pending)
    {
        _handle_trigger_int(dispatcher);
    }

    if (dispatcher->destroy_pending)
    {
        jw_event_dispatcher_destroy(dispatcher);
    }
}

static void _clean_event(bool replace, bool delete_key, void *key, void *data)
{
    UNUSED_PARAM(key);
    UNUSED_PARAM(delete_key);
#ifdef NDEBUG
    UNUSED_PARAM(replace);
#else
    assert(!replace);
#endif

    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    jw_event *event = data;
    jw_event_binding_t *curr = event->bindings;

    /* Clean up callbacks */
    while (curr != NULL)
    {
        jw_event_binding_t *remove = curr;
        curr = curr->next;
        jw_data_free(remove);
        remove = NULL;
    }

    jw_data_free((char *)jw_event_get_name(event));
    jw_data_free(event);
}

static bool _prepare_trigger(jw_event_dispatcher *dispatch,
        jw_event_trigger_data **trigger_data, jw_err *err)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(trigger_data);

    union
    {
        jw_event_trigger_data *tdata;
        void                 *tdataPtr;
    } tdataUnion;

    jw_pool *pool;

    union
    {
        jw_event_moment_t *moment;
        void              *momentPtr;
    } momentUnion;

    if (!jw_pool_create(MOMENT_POOLSIZE, &pool, err))
    {
        jw_log(JW_LOG_WARN, "unable to allocate pool with block size %zd",
               MOMENT_POOLSIZE);
        return false;
    }

    if (!jw_pool_malloc(pool,
                        sizeof(struct _jw_event_moment_t),
                        &momentUnion.momentPtr,
                        err))
    {
        jw_log(JW_LOG_WARN, "unable to allocate moment");
        jw_pool_destroy(pool);
        return false;
    }

    memset(momentUnion.momentPtr, 0, sizeof(struct _jw_event_moment_t));

    // if we're using a workq, create the item
    jw_workq_item *item = NULL;
    if (NULL != dispatch->workq)
    {
        if (!jw_workq_item_create(dispatch->workq, _handle_trigger, &item, err))
        {
            jw_log(JW_LOG_WARN, "unable to allocate workq item");
            jw_pool_destroy(pool);
            return false;
        }
        jw_workq_item_set_data(item, dispatch, NULL);
        momentUnion.moment->workq_item = item;
    }

    if (!jw_pool_malloc(pool,
                        sizeof(jw_event_trigger_t), &tdataUnion.tdataPtr, err))
    {
        jw_log(JW_LOG_WARN, "unable to allocate event trigger data");
        if (item)
        {
            jw_workq_item_destroy(item);
        }
        jw_pool_destroy(pool);
        return false;
    }

    tdataUnion.tdata->pool = pool;
    tdataUnion.tdata->moment = momentUnion.moment;
    *trigger_data = tdataUnion.tdata;

    return true;
}

static void _trigger_prepared(
        jw_event_dispatcher *dispatch,
        jw_event *event,
        void *data,
        jw_event_result_callback result_cb,
        void *result_arg,
        jw_event_trigger_data *trigger_data)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(event);
    assert(trigger_data);
    assert(trigger_data->pool);
    assert(trigger_data->moment);

    jw_event_data       evt;
    jw_event_moment_t  *moment;

    jw_log(JW_LOG_DEBUG, "triggering event '%s'", event->name);

    moment = trigger_data->moment;

    /* setup the event moment */
    moment->result_cb = result_cb;
    moment->result_arg = result_arg;
    moment->bindings = event->bindings;

    /* setup event data */
    evt = &moment->evt;
    evt->source = dispatch->source;
    evt->name = event->name;
    evt->notifier = event;
    evt->data = data;
    evt->selected = NULL;
    evt->pool = trigger_data->pool;
    evt->handled = false;

    // enqueue, and maybe run
    // do not use the dispatcher after this line as it may have been destroyed
    _dispatch_trigger(dispatch, moment);
}


/* External Functions */
JABBERWERX_API bool jw_event_dispatcher_create(void *source,
                                               jw_workq *workq,
                                               jw_event_dispatcher **outdispatch,
                                               jw_err *err)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(source != NULL);
    assert(outdispatch != NULL);

    jw_htable            *events   = NULL;
    jw_event_dispatch_t *dispatch = NULL;

    if (!jw_htable_create(DISPATCH_BUCKETS,
                          jw_strcase_hashcode,
                          jw_strcase_compare,
                          &events,
                          err))
    {
        return false;
    }

    dispatch = jw_data_malloc(sizeof(jw_event_dispatch_t));
    if (dispatch == NULL)
    {
        JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
        jw_htable_destroy(events);
        return false;
    }

    PUSH_EVENTING_NDC;
    jw_log(JW_LOG_TRACE, "creating new event dispatcher");

    memset(dispatch, 0, sizeof(jw_event_dispatch_t));
    dispatch->source = source;
    dispatch->events = events;
    dispatch->workq  = workq;
    *outdispatch = dispatch;

    POP_EVENTING_NDC;

    return true;
}

JABBERWERX_API void jw_event_dispatcher_destroy(jw_event_dispatcher *dispatch)
{
    PUSH_EVENTING_NDC;
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(dispatch != NULL);

    if (NULL != dispatch->running)
    {
        jw_log(JW_LOG_DEBUG,
               "currently processing events; deferring dispatcher destruction");
        dispatch->destroy_pending = true;
        POP_EVENTING_NDC;
        return;
    }

    jw_log(JW_LOG_DEBUG, "destroying dispatcher");
    
    jw_event_moment_t *moment = dispatch->next_moment;
    while (moment)
    {
        jw_event_moment_t *next_moment = moment->next;
        _moment_destroy(moment);
        moment = next_moment;
    }

    jw_htable_destroy(dispatch->events);
    jw_data_free(dispatch);

    POP_EVENTING_NDC;
}

JABBERWERX_API jw_workq *jw_event_dispatcher_get_workq(
        jw_event_dispatcher *dispatch)
{
    PUSH_EVENTING_NDC;
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(dispatch);

    POP_EVENTING_NDC;

    return dispatch->workq;
}

JABBERWERX_API jw_event *jw_event_dispatcher_get_event(
                        jw_event_dispatcher *dispatch,
                        const char *name)
{
    PUSH_EVENTING_NDC;
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(dispatch);

    jw_event *evt = jw_htable_get(dispatch->events, name);

    POP_EVENTING_NDC;

    return evt;
}

JABBERWERX_API bool jw_event_dispatcher_create_event(
                    jw_event_dispatcher *dispatch,
                    const char *name,
                    jw_event **event,
                    jw_err *err)
{
    PUSH_EVENTING_NDC;
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    jw_event_notifier_t *notifier = NULL;
    char                *evt_name = NULL;
    bool                 retval   = true;

    assert(dispatch);
    assert(name);

    if (name[0] == '\0')
    {
        JABBERWERX_ERROR(err, JW_ERR_INVALID_ARG);
        retval = false;
        goto jw_event_dispatcher_create_event_done_label;
    }
    if (jw_htable_get(dispatch->events, name) != NULL)
    {
        JABBERWERX_ERROR(err, JW_ERR_INVALID_STATE);
        retval = false;
        goto jw_event_dispatcher_create_event_done_label;
    }

    size_t nameLen = jw_strlen(name);
    evt_name = (char *)jw_data_malloc(nameLen + 1);
    if (evt_name == NULL)
    {
        JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
        retval = false;
        goto jw_event_dispatcher_create_event_done_label;
    }
    memcpy(evt_name, name, nameLen + 1);

    notifier = jw_data_malloc(sizeof(jw_event_notifier_t));
    if (notifier == NULL)
    {
        JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
        retval = false;
        goto jw_event_dispatcher_create_event_done_label;
    }

    memset(notifier, 0, sizeof(jw_event_notifier_t));
    notifier->dispatcher = dispatch;
    notifier->source = dispatch->source;
    notifier->name = evt_name;

    if (!jw_htable_put(dispatch->events,
                       evt_name,
                       notifier,
                       _clean_event,
                       err))
    {
        retval = false;
        goto jw_event_dispatcher_create_event_done_label;
    }
    evt_name = NULL;

    if (event)
    {
        *event = notifier;
    }
    notifier = NULL;

jw_event_dispatcher_create_event_done_label:
    if (evt_name != NULL)
    {
        jw_data_free((char *)evt_name);
        evt_name = NULL;
    }

    if (notifier != NULL)
    {
        jw_data_free(notifier);
        notifier = NULL;
    }

    POP_EVENTING_NDC;
    return retval;
}

JABBERWERX_API const char *jw_event_get_name(jw_event *event)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(event);

    return event->name;
}

JABBERWERX_API const void *jw_event_get_source(jw_event *event)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(event);

    return event->source;
}

JABBERWERX_API bool jw_event_bind(jw_event                 *event,
                                  jw_event_notify_callback cb,
                                  void                    *arg,
                                  jw_err                  *err)
{
    assert(event);
    assert(cb);

    jw_event_dispatcher *dispatch = event->dispatcher;
    PUSH_EVENTING_NDC;
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    jw_event_binding_t *binding = NULL;
    jw_event_binding_t *prev    = NULL;

    /* look for existing binding first */
    if (!_remove_binding(event, cb, &binding, &prev))
    {
        /* no match found; allocate a new one */
        binding = jw_data_malloc(sizeof(jw_event_binding_t));
        if (binding == NULL)
        {
            JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
            POP_EVENTING_NDC;
            return false;
        }
        memset(binding, 0, sizeof(jw_event_binding_t));
    }
    else
    {
        /* Keep previous binding status so that we know whether it is
         * bound before the current event or within the current event
         */
        bool normal_bound = binding->normal_bound;
        memset(binding, 0, sizeof(jw_event_binding_t));
        binding->normal_bound = normal_bound;
    }

    /* update binding properties */
    binding->cb = cb;
    binding->arg = arg;

    /* (re-)insert into list */
    if (event->bindings == NULL)
    {
        /* first binding; place on the front */
        event->bindings = binding;
    }
    else if (prev != NULL)
    {
        /* append the binding to the end */
        if (prev->next == NULL)
        {
            prev->next = binding;
        }
        else
        {
            binding->next = prev->next;
            prev->next = binding;
        }
    }
    else // prev == NULL
    {
        binding->next = event->bindings;
        event->bindings = binding;
    }

    POP_EVENTING_NDC;
    return true;
}

JABBERWERX_API void jw_event_unbind(jw_event *event,
                                    jw_event_notify_callback cb)
{
    assert(event);
    assert(event->dispatcher);
    assert(cb);

    jw_event_dispatcher *dispatch = event->dispatcher;
    PUSH_EVENTING_NDC;
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    /* If we're currently running the event we're requesting the unbind from
     * we need to defer the operation until the event has finished its
     * trigger
     */
    if (event != event->dispatcher->running)
    {
        jw_event_binding_t *binding;
        if (_remove_binding(event, cb, &binding, NULL))
        {
            /* match found; lists already updated */
            jw_data_free(binding);
            binding = NULL;
        }
    }
    else
    {
        // we are guaranteed to find the event (even if it is already unbound)
        jw_event_binding_t *cur = event->bindings;
        while (true)
        {
            if (cur->cb == cb)
            {
                cur->unbound = true;
                break;
            }

            cur = cur->next;
            assert(cur);
        }
    }

    POP_EVENTING_NDC;
}

JABBERWERX_API bool jw_event_prepare_trigger(jw_event_dispatcher *dispatch,
        jw_event_trigger_data **trigger_data, jw_err *err)
{
    PUSH_EVENTING_NDC;
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    bool ret = _prepare_trigger(dispatch, trigger_data, err);

    POP_EVENTING_NDC;
    return ret;
}

JABBERWERX_API void jw_event_unprepare_trigger(
        jw_event_trigger_data *trigger_data)
{
    assert(trigger_data);
    assert(trigger_data->moment);

    jw_event *evt = trigger_data->moment->evt.notifier;

    jw_event_dispatcher *dispatch = evt ? evt->dispatcher : NULL;

    PUSH_EVENTING_NDC;
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    jw_pool_destroy(trigger_data->pool);

    POP_EVENTING_NDC;
}

JABBERWERX_API void jw_event_trigger_prepared(
        jw_event                 *event,
        void                    *data,
        jw_event_result_callback result_cb,
        void                    *result_arg,
        jw_event_trigger_data    *trigger_data)
{
    assert(event);

    jw_event_dispatcher *dispatch = event->dispatcher;

    PUSH_EVENTING_NDC;
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    _trigger_prepared(dispatch, event, data,
                      result_cb, result_arg, trigger_data);

    POP_EVENTING_NDC;
}

JABBERWERX_API bool jw_event_trigger(jw_event *event,
                                     void *data,
                                     jw_event_result_callback result_cb,
                                     void *result_arg,
                                     jw_err *err)
{
    assert(event);

    jw_event_dispatcher *dispatch = event->dispatcher;

    PUSH_EVENTING_NDC;
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    jw_event_trigger_data *trigger_data;

    if (!_prepare_trigger(dispatch, &trigger_data, err))
    {
        POP_EVENTING_NDC;
        return false;
    }

    _trigger_prepared(dispatch, event, data,
                      result_cb, result_arg, trigger_data);

    POP_EVENTING_NDC;

    return true;
}
