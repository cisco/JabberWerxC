/**
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

#include <assert.h>
#include <string.h>
#include <time.h>
#include "../include/timer.h"
#include <jabberwerx/util/log.h>

#define MS_PER_SECOND 1000

struct _jw_timer
{
    jw_workq              *workq;
    jw_event_dispatcher   *dispatch;
    uint32_t                    timeout_ms;
    time_t                      last_activity_timestamp_s;
    time_t                      last_activity_timestamp_at_timer_scheduled_s;
    jw_workq_item         *timer;
    jw_event_trigger_data *on_error_trigger_data;
};


static void _on_error(jw_timer *timer)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    jw_event_trigger_data *trigger_data = timer->on_error_trigger_data;
    timer->on_error_trigger_data = NULL;

    jw_event_trigger_prepared(
            jw_timer_event(timer, JW_TIMER_EVENT_ERROR),
            NULL, NULL, NULL, trigger_data);
}

static void _schedule_timer(jw_timer *timer, uint32_t delay_ms)
{
    JW_LOG_TRACE_FUNCTION("delay_ms=%u", delay_ms);

    jw_err err;

    timer->last_activity_timestamp_at_timer_scheduled_s =
            timer->last_activity_timestamp_s;

    if (!jw_workq_item_set_delay(timer->timer, delay_ms, &err))
    {
        jw_log_err(JW_LOG_WARN, &err, "failed to set timer delay");
        _on_error(timer);
        return;
    }

    if (!jw_workq_item_append(timer->timer, &err))
    {
        jw_log_err(JW_LOG_ERROR, &err,
                   "failed to schedule unscheduled timeout timer");
        assert(false);
    }
}

static void _timeout_handler(jw_workq_item *item, void *data)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    UNUSED_PARAM(item);
    jw_timer *timer = data;
    assert(timer);

    // if the timestamp of the last activity is unchanged, alert
    if (timer->last_activity_timestamp_s ==
            timer->last_activity_timestamp_at_timer_scheduled_s)
    {
        jw_err err;
        if (!jw_event_trigger(
                jw_timer_event(timer, JW_TIMER_EVENT_TIMEOUT),
                NULL, NULL, NULL, &err))
        {
            jw_log_err(JW_LOG_WARN, &err, "failed to trigger timeout event");
            _on_error(timer);
        }
    }
    else
    {
        // reschedule for partial timeout duration
        time_t now = time(NULL);
        uint32_t remaining_delay_ms = timer->timeout_ms -
           MS_PER_SECOND*(now - timer->last_activity_timestamp_s);

        if (timer->timeout_ms < remaining_delay_ms)
        {
            jw_log(JW_LOG_WARN, "correcting for clock skew in timeout timer");
            remaining_delay_ms = timer->timeout_ms;
        }

        _schedule_timer(timer, remaining_delay_ms);
    }
}

bool jw_timer_create(jw_workq  *workq,
                     jw_timer **timer,
                     jw_err         *err)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(timer);

    jw_timer *ret = jw_data_malloc(sizeof(struct _jw_timer));
    if (!ret)
    {
        JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
        return false;
    }
    memset(ret, 0, sizeof(struct _jw_timer));

    if (!jw_event_dispatcher_create(ret, workq, &ret->dispatch, err)
     || !jw_event_dispatcher_create_event(ret->dispatch,
                    JW_TIMER_EVENT_TIMEOUT, NULL, err)
     || !jw_event_dispatcher_create_event(ret->dispatch,
                    JW_TIMER_EVENT_ERROR, NULL, err)
     || !jw_workq_item_create(workq, _timeout_handler, &ret->timer, err)
     || !jw_event_prepare_trigger(
                    ret->dispatch, &ret->on_error_trigger_data, err))
    {
        goto jw_timer_create_fail_label;
    }

    jw_workq_item_set_data(ret->timer, ret, NULL);

    ret->workq = workq;

    *timer = ret;
    return true;

jw_timer_create_fail_label:
    jw_timer_destroy(ret);
    return false;
}

void jw_timer_destroy(jw_timer *timer)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;
    assert(timer);

    if (timer->dispatch)
    {
        jw_event_dispatcher_destroy(timer->dispatch);
    }
    if (timer->on_error_trigger_data)
    {
        jw_event_unprepare_trigger(timer->on_error_trigger_data);
    }
    if (timer->timer)
    {
        jw_workq_item_destroy(timer->timer);
    }

    jw_data_free(timer);
}

jw_event *jw_timer_event(jw_timer *timer, const char *name)
{
    JW_LOG_TRACE_FUNCTION("name=%s", name);
    assert(timer);
    assert(name != NULL && *name != '\0');
    return jw_event_dispatcher_get_event(timer->dispatch, name);
}

void jw_timer_cancel(jw_timer *timer)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;
    assert(timer);
    jw_workq_item_cancel(timer->timer);
}

void jw_timer_set_inactivity_timeout(
        jw_timer *timer, uint32_t timeout_ms)
{
    JW_LOG_TRACE_FUNCTION("timeout_ms=%d", timeout_ms);
    assert(timer);
    timer->timeout_ms = timeout_ms;
}

void jw_timer_mark_activity(jw_timer *timer)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;
    assert(timer);
    timer->last_activity_timestamp_s = time(NULL);
    if (!jw_workq_item_is_scheduled(timer->timer))
    {
        _schedule_timer(timer, timer->timeout_ms);
    }
}
