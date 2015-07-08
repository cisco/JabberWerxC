/**
 * \file
 * \brief
 * Eventing typedefs. private, not for use outside library and unit tests.
 * \see eventing.h
 *
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

#ifndef JABBERWERX_EVENTING_INT_H
#define JABBERWERX_EVENTING_INT_H

#include "jabberwerx/eventing.h"
#include "jabberwerx/util/htable.h"

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * Event binding information. This structure is created for each call to
 * jw_event_bind with a unique callback.
 */
typedef struct _jw_event_binding_t
{
    jw_event_notify_callback    cb;
    void                        *arg;
    struct _jw_event_binding_t  *next;
    bool                        unbound;
    /**
     * Binding status. True if it is already bound before an event is
     * triggered. It is false by default and marked as true at the very
     * beginning of an event trigger. Within an event trigger, false
     * implies a callback that is bound in the current event and should
     * not be executed until the next time this event is triggered.
     */
    bool                        normal_bound;
} jw_event_binding_t;

/**
 * Event triggering information. This describes a "moment in time" of an
 * event.
 */
typedef struct _jw_event_moment_t
{
    struct _jw_event_data_t         evt;
    jw_workq_item                   *workq_item;
    jw_event_result_callback        result_cb;
    void                            *result_arg;
    jw_event_binding_t              *bindings;
    struct _jw_event_moment_t       *next;
} jw_event_moment_t;

/**
 * Dispatcher members. This is the structure underlying jw_event_dispatcher.
 */
typedef struct _jw_event_dispatch_t
{
    void                    *source;
    jw_htable               *events;
    jw_event                *running;
    jw_event_moment_t       *moment_queue_tail;
    jw_event_moment_t       *next_moment;
    jw_workq                *workq;
    bool                    destroy_pending;
} jw_event_dispatch_t;

/**
 * Notifier members. This is the structure underlying jw_event.
 */
typedef struct _jw_event_t
{
    jw_event_dispatch_t *dispatcher;
    const void          *source;
    const char          *name;
    jw_event_binding_t  *bindings;
} jw_event_notifier_t;

#ifdef __cplusplus
}
#endif

#endif /* JABBERWERX_EVENTING_INT_H */
