/**
 * \file
 * \brief
 * Functions and data structures for eventing.
 *
 * Each source that generates events SHOULD export a &lt;source_type&gt;_event
 * function that returns a named event, or NULL if it does not exist.
 * \code
 * jw_event <source_type>_event(<source_type> source, const char *name)
 * \endcode
 *
 * The name should match lexically in an ASCII case-insensitive manner.
 *
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */
 
#ifndef JABBERWERX_EVENTING_H
#define JABBERWERX_EVENTING_H

#include "util/mem.h"
#include "util/workq.h"


/**
 * Datatype for an event dispatcher. Each event source contains an event
 * dispatcher. It creates and manages events, and regulates any event
 * triggerings for its owned events.
 */
typedef struct _jw_event_dispatch_t jw_event_dispatcher;

/**
 * Datatype for an event (notifier). It manages the callbacks and triggerings
 * for a given event.
 */
typedef struct _jw_event_t jw_event;

/** Data used by an event trigger. */
typedef struct _jw_event_trigger_t jw_event_trigger_data;

/** Event data passed to bound callbacks. */
typedef struct _jw_event_data_t
{
    /** Event source */
    void       *source;
    /** Event name */
    const char *name;
    /** Event object */
    jw_event   *notifier;
    /** Data specific to this triggering of an event */
    void       *data;
    /** Possible selection. Reserved for future use. */
    void       *selected;
    /** Pool to use for any modification to this event data */
    jw_pool    *pool;
    /**
      * Flag to indicate the event has been handled in some manner.
      * Callbacks may set this value to true; the eventing logic will
      * ensure this value, once set to true, is propagated to all further
      * callbacks for this event.
      */
    bool        handled;
} *jw_event_data;

/**
 * Callback executed when an event is triggered. Callbacks should set the
 * handled flag in the jw_event_data to true to indicate the event was handled.
 *
 * \param[in] evt Event information
 * \param[in] arg An argument bound to this callback
 */
typedef void (*jw_event_notify_callback)(jw_event_data evt,
                                         void         *arg);

/**
 * Callback executed when an event triggering is complete.
 *
 * \param[in] evt Event information
 * \param[in] result True if any notify callbacks returned true, false
 *            otherwise
 * \param[in] arg The user-provided data when the event was triggered
 */
typedef void (*jw_event_result_callback)(jw_event_data evt,
                                         bool          result,
                                         void         *arg);


#ifdef __cplusplus
extern "C"
{
#endif

/**
 * Creates a new jw_event_dispatcher for the given source.  Depending on the
 * value of the workq parameter, the dispatcher can be synchronous (events fire
 * before a call to trigger returns) or asynchronous (events are enqueued on
 * a workq and fire from the libevent event queue).
 *
 * This function can generate the following errors (set when returning false):
 * \li \c JW_ERR_NO_MEMORY if the dispatcher could not be allocated
 *
 * \invariant source != NULL
 * \invariant dispatch != NULL
 * \param[in] source The event source
 * \param[in] workq The work queue.  If NULL, the dispatcher will be
 *      synchronous, if non-NULL, asynchronous
 * \param[out] dispatch The created event dispatcher
 * \param[out] err The error information (provide NULL to ignore)
 * \retval bool True if the dispatcher was created successfully.
 */
JABBERWERX_API bool jw_event_dispatcher_create(void                 *source,
                                               jw_workq             *workq,
                                               jw_event_dispatcher **dispatch,
                                               jw_err               *err);

/**
 * Destroys the given dispatcher and frees its resources.  If the handler for
 * an event is currently running, the destruction is deferred until the handler
 * returns.
 *
 * \b NOTE: Any remaining scheduled event handlers will not execute.
 *
 * \invariant dispatch != NULL
 * \param[in] dispatch The event dispatcher
 */
JABBERWERX_API void jw_event_dispatcher_destroy(jw_event_dispatcher *dispatch);

/**
 * Retrieves the workq used by the given dispatcher.
 *
 * \invariant dispatch != NULL
 * \param[in] dispatch The event dispatcher
 * \retval jw_workq The workq used by the dispatcher
 */
JABBERWERX_API jw_workq *jw_event_dispatcher_get_workq(
        jw_event_dispatcher *dispatch);

/**
 * Retrieves the event notifier from the dispatcher for the given name. Events are
 * matched using an ASCII case-insensitive lookup.
 *
 * \invariant dispatch != NULL
 * \invariant name != NULL
 * \param[in] dispatch The event dispatcher
 * \param[in] name The event name
 * \retval jw_event_notifier The event notifier, or NULL if not found
 */
JABBERWERX_API jw_event *jw_event_dispatcher_get_event(
        jw_event_dispatcher *dispatch,
        const char          *name);

/**
 * Create a new event for the given dispatcher and event name. When
 * created, this event is registered with the given dispatcher and can be
 * accessed via jw_event_dispatcher_get_event().
 *
 * \b NOTE: The event name is case-insensitive; while the original value may
 * be retained, most uses use a "lower-case" variant.
 * \b NOTE: The event name is assumed to be ASCII letters and numbers; no
 * attempt is made to validate or enforce this restriction
 *
 * This function can generate the following errors (set when returning false):
 * \li \c JW_ERR_NO_MEMORY if the event could not be allocated
 * \li \c JW_ERR_INVALID_ARG if {name} is the empty string
 * \li \c JW_ERR_INVALID_STATE if an event for {name} already exists in
 *     {dispatch}
 *
 * \invariant dispatch != NULL
 * \invariant name != NULL
 * \param[in] dispatch The owning event dispatcher
 * \param[in] name The event name
 * \param[out] event The created event (provide NULL to ignore)
 * \param[out] err The error information (provide NULL to ignore)
 * \retval bool True if the event was created successfully.
 */
JABBERWERX_API bool jw_event_dispatcher_create_event(
        jw_event_dispatcher *dispatch,
        const char          *name,
        jw_event           **event,
        jw_err              *err);

/**
 * Retrieves the name of this event. The value returned by this function is
 * owned by the event, and its memory is released when the event is destroyed.
 *
 * \invariant event != NULL
 * \param[in] event The event
 * \retval const char * The name of the event
 */
JABBERWERX_API const char *jw_event_get_name(jw_event *event);

/**
 * Retrieves the source for the given event.
 *
 * \invariant event != NULL
 * \param[in] event The event
 * \retval void * The event source
 */
JABBERWERX_API const void *jw_event_get_source(jw_event *event);

/**
 * Binds the given callback to the event.
 *
 * \b NOTE: Callbacks are unique by their pointer reference. Registering the
 * same function multiple times has no effect and will not change binding
 * list position.
 *
 * This function can generate the following errors (set when returning false):
 * \li \c JW_ERR_NO_MEMORY if the binding could not be allocated
 *
 * \invariant event != NULL
 * \invariant cb != NULL
 * \param[in] event The event
 * \param[in] cb The callback to execute when the event is triggered
 * \param[in] arg User-provided data for the callback
 * \param[out] err The error information (provide NULL to ignore)
 * \retval bool True if the callback was successfully bound.
 */
JABBERWERX_API bool jw_event_bind(jw_event                *event,
                                  jw_event_notify_callback cb,
                                  void                    *arg,
                                  jw_err                  *err);

/**
 * Unbinds the given event callback. If {cb} is not currently bound to the
 * event, this function does nothing.
 *
 * \invariant event != NULL
 * \invariant cb != NULL
 * \param[in] event The event
 * \param[in] cb The callback to unbind
 */
JABBERWERX_API void jw_event_unbind(jw_event                *event,
                                    jw_event_notify_callback cb);

/**
 * Fires an event on all registered callbacks, with the given data.
 * Triggered events are handled in a "breadth-first" fashion; events triggered
 * within an event callback are added to an event queue and processed when the
 * triggering callback returns. Each source has its own event queue.
 *
 * This function can generate the following errors (set when returning false):
 * \li \c JW_ERR_NO_MEMORY if the triggering info could not be allocated
 *
 * \invariant event != NULL
 * \param[in] event The event
 * \param[in] data The data for this event triggering
 * \param[in] result_cb Callback to receive trigger result
 * \param[in] result_arg User-specific data for result_cb
 * \param[out] err The error information (provide NULL to ignore)
 * \retval bool True if the callback was successfully bound.
 */
JABBERWERX_API bool jw_event_trigger(jw_event                *event,
                                     void                    *data,
                                     jw_event_result_callback result_cb,
                                     void                    *result_arg,
                                     jw_err                  *err);

/**
 * Same as jw_event_trigger except that no internal allocation takes place,
 * ensuring the trigger succeeds, even in low memory conditions.
 *
 * \invariant event != NULL
 * \invariant trigger_data != NULL
 * \param[in] event The event
 * \param[in] data The data for this event triggering
 * \param[in] result_cb Callback to receive trigger result
 * \param[in] result_arg User-specific data for result_cb
 * \param[in] trigger_data The preallocated structures to use for the callback.
 *                         This will be cleaned up by the triggering mechanism.
 */
JABBERWERX_API void jw_event_trigger_prepared(
        jw_event                *event,
        void                    *data,
        jw_event_result_callback result_cb,
        void                    *result_arg,
        jw_event_trigger_data   *trigger_data);

/**
 * Pre-allocates the data structures for a single call to
 * jw_event_trigger_prepared.
 *
 * This function can generate the following errors (set when returning false):
 * \li \c JW_ERR_NO_MEMORY if the triggering info could not be allocated
 *
 * \invariant trigger_data != NULL
 * \param[in] dispatch The event dispatcher
 * \param[out] trigger_data The created structure
 * \param[out] err The error information (provide NULL to ignore)
 * \retval bool True if the structures were successfully allocated
 */
JABBERWERX_API bool jw_event_prepare_trigger(jw_event_dispatcher *dispatch,
        jw_event_trigger_data **trigger_data, jw_err *err);

/**
 * Destroys unused trigger data.  Trigger data is normally destroyed by
 * jw_event_trigger_prepared(), but this call is provided for the case where
 * trigger data is prepared but the prepared event is never triggered.
 *
 * \invariant trigger_data != NULL
 * \param[in] trigger_data The structure to be destroyed
 */
JABBERWERX_API void jw_event_unprepare_trigger(
        jw_event_trigger_data *trigger_data);

#ifdef __cplusplus
}
#endif

#endif /* JABBERWERX_EVENTING_H */
