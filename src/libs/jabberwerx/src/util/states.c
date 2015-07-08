/**
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

#include <jabberwerx/util/states.h>
#include <jabberwerx/util/log.h>
#include <assert.h>
#include <string.h>


/*
 * Internal structure definitions
 */

typedef struct _bind_info_int
{
    jw_event                 *evt;
    jw_event_notify_callback cb;
    void                    *arg;
    struct _bind_info_int   *prev;
} *_bind_info;

typedef struct _state_info_int
{
    char      *name;

    // track the tail instead of the head so appends are O(1) while leaving
    // list walks no more than the required O(N)
    _bind_info bind_info_list_tail;
} _state_info;

struct _jw_states
{
    jw_state_val        current;
    jw_state_val        max_state_val;
    jw_event_dispatcher *dispatcher;
    _state_info         state_infos[];
};

struct _jw_states_event_data
{
    jw_state_val next;
    jw_state_val prev;
    void        *extra;
};

typedef struct _result_data_int
{
    jw_data_free_func    extra_cleaner;
    jw_states_event_data *event_data;
} *_result_data;


/*
 * Internal functions
 */

#define PUSH_STATES_NDC int _ndcDepth = _push_states_ndc(states, __func__)
#define POP_STATES_NDC jw_log_pop_ndc(_ndcDepth)
static int _push_states_ndc(jw_states *states, const char *entrypoint)
{
    assert(states);
    assert(entrypoint);

    return jw_log_push_ndc("states=%p; entrypoint=%s",
                           (void *)states, entrypoint);
}

// returns the _bind_info in collection that matches the evt and cb fields in
// target, or NULL if not found
static _bind_info _find_bind_info(_bind_info target, _state_info *collection)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(target);
    assert(collection);

    _bind_info cur_bind_info = collection->bind_info_list_tail;
    while (cur_bind_info)
    {
        if (target->evt == cur_bind_info->evt &&
            target->cb  == cur_bind_info->cb)
        {
            jw_log(JW_LOG_DEBUG, "found target");
            return cur_bind_info;
        }
        
        cur_bind_info = cur_bind_info->prev;
    }

    jw_log(JW_LOG_DEBUG, "target not found in specified collection");
    return NULL;
}

// binds events in list order (that is, from head to tail).
// returns _bind_info that had an error, or NULL if no error was encountered
static _bind_info _bind_for_next_state(_bind_info cur_bind_info, jw_err *err)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    if (!cur_bind_info)
    {
        return NULL;
    }

    _bind_info ret = _bind_for_next_state(cur_bind_info->prev, err);
    if (NULL == ret)
    {
        if (!jw_event_bind(cur_bind_info->evt, cur_bind_info->cb,
                           cur_bind_info->arg, err))
        {
            jw_log(JW_LOG_WARN, "unable to bind event for next state");
            ret = cur_bind_info;
        }
    }

    return ret;
}

// recovers from a binding error by restoring the binds for the previous state
// returns whether we've successfully processed up to bad_bind_info
static bool _undo_bind_for_next_state(_bind_info   cur_bind_info,
                                      _bind_info   bad_bind_info,
                                      _state_info *prev_state_info)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    jw_err err;

    if (!cur_bind_info)
    {
        return false;
    }

    if(_undo_bind_for_next_state(
            cur_bind_info->prev, bad_bind_info, prev_state_info) ||
       cur_bind_info == bad_bind_info)
    {
        // bad_bind_info already seen; no more processing to do
        return true;
    }

    // reinstate the current state's event callbacks
    _bind_info prev_bind_info = _find_bind_info(cur_bind_info, prev_state_info);

    if (NULL == prev_bind_info)
    {
        jw_event_unbind(cur_bind_info->evt, cur_bind_info->cb);
    }
    else if (!jw_event_bind(prev_bind_info->evt, prev_bind_info->cb,
                            prev_bind_info->arg, &err))
    {
        // rebinding does not allocate memory and should never fail,
        // unless, of course, the implementation changes, at which point
        // this logic should be revisited.
        jw_log_err(JW_LOG_ERROR, &err, "unable to rebind previous event");
        assert(false);
    }

    return false;
}

// frees memory allocated for the state change event
static void _state_change_result_cb (jw_event_data evt, bool result, void *arg)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    UNUSED_PARAM(evt);
    UNUSED_PARAM(result);

    assert(evt);
    assert(arg);

    _result_data result_data = arg;
    jw_states_event_data *event_data = result_data->event_data;

    jw_data_free_func extra_cleaner = result_data->extra_cleaner;
    if (extra_cleaner)
    {
        extra_cleaner(event_data->extra);
    }
    jw_data_free(event_data);
    jw_data_free(result_data);
}


/*
 * Public API
 */

JABBERWERX_API bool jw_states_create(const char **names,
                                     jw_state_val initial,
                                     jw_workq     *workq,
                                     jw_states   **retstates,
                                     jw_err      *err)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(names);
    assert(workq);
    assert(retstates);

    // determine length of names array
    const char **cur_name = names;
    while (NULL != *cur_name)
    {
        ++cur_name;
    }
    int num_states = cur_name - names;

    // verify ranges
    if (num_states >= (1 << (sizeof(jw_state_val) * 8)))
    {
        jw_log(JW_LOG_WARN, "too many states to represent: %d", num_states);
        JABBERWERX_ERROR(err, JW_ERR_INVALID_ARG);
        return false;
    }

    // this also catches the case of a 0-length names array
    if (initial >= num_states)
    {
        jw_log(JW_LOG_WARN,
               "initial state beyond bounds of known states:"
               " %d must be less than %d",
               initial, num_states);
        JABBERWERX_ERROR(err, JW_ERR_INVALID_ARG);
        return false;
    }
    jw_log(JW_LOG_DEBUG,
           "initializing states object with %d states", num_states);

    // create states object to return
    int new_states_size = sizeof(struct _jw_states) +
                          (sizeof(struct _state_info_int) * num_states);
    jw_states *states = jw_data_malloc(new_states_size);
    if (NULL == states)
    {
        jw_log(JW_LOG_WARN, "unable to allocate states object");
        JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
        return false;
    }
    memset(states, 0, new_states_size);

    PUSH_STATES_NDC;

    // initialize simple data
    states->current = initial;
    states->max_state_val = num_states - 1;

    // initialize state_info elements
    cur_name = names;
    _state_info *cur_info = &states->state_infos[0];
    while (NULL != *cur_name)
    {
        cur_info->name = jw_data_strdup(*cur_name);

        if (!cur_info->name)
        {
            jw_log(JW_LOG_WARN, "unable to allocate memory for state name");
            JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
            goto jw_states_create_fail_label;
        }

        ++cur_name;
        ++cur_info;
    }

    // initialize dispatcher
    if (!jw_event_dispatcher_create(states, workq, &states->dispatcher, err))
    {
        jw_log(JW_LOG_WARN, "unable to allocate dispatcher");
        goto jw_states_create_fail_label;
    }

    if (!jw_event_dispatcher_create_event(states->dispatcher,
                JW_STATES_EVENT, NULL, err))
    {
        jw_log(JW_LOG_WARN, "unable to create state change event");
        goto jw_states_create_fail_label;
    }

    *retstates = states;
    POP_STATES_NDC;
    return true;

jw_states_create_fail_label:
    jw_states_destroy(states);
    POP_STATES_NDC;
    return false;
}

JABBERWERX_API void jw_states_destroy(jw_states *states)
{
    PUSH_STATES_NDC;
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(states);

    if (states->dispatcher)
    {
        jw_event_dispatcher_destroy(states->dispatcher);
        states->dispatcher = NULL;
    }

    jw_state_val max_state_val = states->max_state_val;
    _state_info *state_infos = states->state_infos;
    for (jw_state_val idx = 0; max_state_val >= idx; ++idx)
    {
        jw_data_free(state_infos[idx].name);

        // free the bind info list elements (but not the contents -- they are
        // not owned by us)
        _bind_info cur_bind_info = state_infos[idx].bind_info_list_tail;
        while (cur_bind_info)
        {
            // unbind events for the current state
            if (states->current == idx)
            {
                jw_event_unbind(cur_bind_info->evt, cur_bind_info->cb);
            }

            _bind_info prev = cur_bind_info->prev;
            jw_data_free(cur_bind_info);
            cur_bind_info = prev;
        }
    }

    jw_data_free(states);
    POP_STATES_NDC;
}

JABBERWERX_API jw_state_val jw_states_get_current(jw_states *states)
{
    JW_LOG_TRACE_FUNCTION("states=%p", (void *)states);

    assert(states);

    return states->current;
}

JABBERWERX_API const char * jw_states_get_name_for(jw_states *states,
                                                   jw_state_val state_val)
{
    JW_LOG_TRACE_FUNCTION("states=%p; state_val=%d", (void *)states, state_val);

    assert(states);

    if (states->max_state_val < state_val)
    {
        return NULL;
    }

    return states->state_infos[state_val].name;
}

JABBERWERX_API bool jw_states_register_for(jw_states *states,
                                           jw_state_val current,
                                           jw_event *evt,
                                           jw_event_notify_callback cb,
                                           void *arg,
                                           jw_err *err)
{
    PUSH_STATES_NDC;
    JW_LOG_TRACE_FUNCTION("current=%d; evt=%p", current, (void *)evt);

    assert(states);
    assert(evt);
    assert(cb);

    _bind_info bind_info = NULL;

    if (states->max_state_val < current)
    {
        jw_log(JW_LOG_WARN, "cannot register for unknown state: %d", current);
        JABBERWERX_ERROR(err, JW_ERR_INVALID_ARG);
        goto jw_states_register_for_fail_label;
    }

    // allocate and fill _bind_info structure
    bind_info = jw_data_malloc(sizeof(struct _bind_info_int));
    if (NULL == bind_info)
    {
        jw_log(JW_LOG_WARN, "unable to allocate memory for registration");
        JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
        goto jw_states_register_for_fail_label;
    }

    bind_info->evt = evt;
    bind_info->cb  = cb;
    bind_info->arg = arg;

    // if the specified state is current, bind immediately
    if (current == states->current)
    {
        if (!jw_event_bind(bind_info->evt, bind_info->cb,
                           bind_info->arg, err))
        {
            jw_log(JW_LOG_WARN, "unable to bind event for current state");
            goto jw_states_register_for_fail_label;
        }
    }

    // append to bind_info list
    _state_info *state_info = &states->state_infos[current];
    bind_info->prev = state_info->bind_info_list_tail;
    state_info->bind_info_list_tail = bind_info;

    POP_STATES_NDC;
    return true;

jw_states_register_for_fail_label:
    jw_data_free(bind_info);
    POP_STATES_NDC;
    return false;
}

JABBERWERX_API bool jw_states_change(jw_states *states,
                                     jw_state_val next,
                                     void *extra,
                                     jw_data_free_func extra_cleaner,
                                     jw_err* err)
{
    PUSH_STATES_NDC;
    JW_LOG_TRACE_FUNCTION("next=%d", next);

    assert(states);

    if (states->current == next)
    {
        jw_log(JW_LOG_DEBUG, "transition to current state requested; noop");
        goto jw_states_change_success_label;
    }

    jw_event_trigger_data *trigger_data = NULL;
    jw_states_event_data  *event_data   = NULL;
    _result_data          result_data  = NULL;

    if (states->max_state_val < next)
    {
        jw_log(JW_LOG_WARN, "unknown next state: %d > %d",
               next, states->max_state_val);
        JABBERWERX_ERROR(err, JW_ERR_INVALID_ARG);
        goto jw_states_change_fail_label;
    }

    // prepare for the transition event (we don't want to change state and only
    // find out later that we can't trigger the state changed event)
    if (!jw_event_prepare_trigger(states->dispatcher, &trigger_data, err))
    {
        jw_log(JW_LOG_WARN, "preparation failed for state change event");
        goto jw_states_change_fail_label;
    }

    // we can't allocate these on the stack since the events may be deferred
    event_data = jw_data_malloc(sizeof(struct _jw_states_event_data));
    if (NULL == event_data)
    {
        jw_log(JW_LOG_WARN, "unable to allocate memory for state change event");
        JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
        goto jw_states_change_fail_label;
    }
    event_data->next  = next;
    event_data->prev  = states->current;
    event_data->extra = extra;

    result_data = jw_data_malloc(sizeof(struct _result_data_int));
    if (NULL == result_data)
    {
        jw_log(JW_LOG_WARN, "unable to allocate memory for state change event");
        JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
        goto jw_states_change_fail_label;
    }
    result_data->event_data = event_data;
    result_data->extra_cleaner = extra_cleaner;

    // bind new handlers
    _state_info *next_state_info = &states->state_infos[next];
    _state_info *prev_state_info = &states->state_infos[states->current];

    _bind_info bad_bind_info =
            _bind_for_next_state(next_state_info->bind_info_list_tail, err);

    if (NULL != bad_bind_info)
    {
        if (!_undo_bind_for_next_state(next_state_info->bind_info_list_tail,
                                       bad_bind_info,
                                       prev_state_info))
        {
            jw_log(JW_LOG_ERROR, "unknown error rolling back partial changes");
            assert(false);
        }

        jw_log(JW_LOG_DEBUG, "successfully rolled back partial changes");
        goto jw_states_change_fail_label;
    }

    // unbind current handlers, skipping the handlers that current and next
    // share, as they have already been overwritten
    _bind_info cur_bind_info = prev_state_info->bind_info_list_tail;
    while (cur_bind_info)
    {
        if (NULL == _find_bind_info(cur_bind_info, next_state_info))
        {
            jw_event_unbind(cur_bind_info->evt, cur_bind_info->cb);
        }
        cur_bind_info = cur_bind_info->prev;
    }
    
    // state transition complete
    states->current = next;

    jw_log(JW_LOG_DEBUG, "firing %s event for states=%p with event_data=%p",
           JW_STATES_EVENT, (void *)states, (void *)event_data);
    jw_event_trigger_prepared(jw_states_event(states, JW_STATES_EVENT),
                              event_data, _state_change_result_cb, result_data,
                              trigger_data);

jw_states_change_success_label:
    POP_STATES_NDC;
    return true;

jw_states_change_fail_label:
    if (NULL != trigger_data)
    {
        jw_event_unprepare_trigger(trigger_data);
    }
    jw_data_free(event_data);
    jw_data_free(result_data);
    POP_STATES_NDC;
    return false;
}

JABBERWERX_API jw_event *jw_states_event(jw_states *states, const char *name)
{
    PUSH_STATES_NDC;
    JW_LOG_TRACE_FUNCTION("name='%s'", name);

    assert(states);
    assert(name != NULL && *name != '\0');

    jw_event *ret = jw_event_dispatcher_get_event(states->dispatcher, name);

    POP_STATES_NDC;
    return ret;
}

JABBERWERX_API jw_state_val jw_states_event_data_get_prev(
        jw_states_event_data *event_data)
{
    JW_LOG_TRACE_FUNCTION("event_data=%p", (void *)event_data);

    assert(event_data);

    return event_data->prev;
}

JABBERWERX_API jw_state_val jw_states_event_data_get_next(
        jw_states_event_data *event_data)
{
    JW_LOG_TRACE_FUNCTION("event_data=%p", (void *)event_data);

    assert(event_data);

    return event_data->next;
}

JABBERWERX_API void * jw_states_event_data_get_extra(
        jw_states_event_data *event_data)
{
    JW_LOG_TRACE_FUNCTION("event_data=%p", (void *)event_data);

    assert(event_data);

    return event_data->extra;
}

/* vim: set sw=4: */
