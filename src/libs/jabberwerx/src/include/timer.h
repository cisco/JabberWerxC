/**
 * \file
 * \brief
 * Inactivity timer.
 *
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

#ifndef JABBERWERX_TIMER_H
#define JABBERWERX_TIMER_H

#include <jabberwerx/eventing.h>
#include <jabberwerx/util/workq.h>

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * Sent at activity timeout
 */
#define JW_TIMER_EVENT_TIMEOUT "timeout"
/**
 * Sent on error
 */
#define JW_TIMER_EVENT_ERROR "error"

typedef struct _jw_timer jw_timer;

bool jw_timer_create(jw_workq  *workq,
                     jw_timer **timer,
                     jw_err         *err);

void jw_timer_destroy(jw_timer *timer);

jw_event *jw_timer_event(jw_timer *timer, const char *name);

// re-enable by calling mark_activity
void jw_timer_cancel(jw_timer *timer);

void jw_timer_set_inactivity_timeout(jw_timer *timer, uint32_t timeout_ms);

void jw_timer_mark_activity(jw_timer *timer);

#ifdef __cplusplus
}
#endif

#endif // JABBERWERX_TIMER_H
