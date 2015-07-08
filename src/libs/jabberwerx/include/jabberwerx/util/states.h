/**
 * \file
 * \brief
 * Functions and data structures for the state management engine.
 *
 * A states object manages the callbacks bound to specified events to ensure
 * only the specified callbacks are bound when this states object is in a
 * particular state.  For the purposes of this object, states are integers
 * between the values of 0 and the length of the "names" array parameter passed
 * into the constructor (max 255 states).
 *
 * The current implementation is not optimized for large numbers of registered
 * callbacks, but could be made so if the need arises.
 *
 *
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

#ifndef JABBERWERX_UTIL_STATES_H
#define JABBERWERX_UTIL_STATES_H


#include "../eventing.h"
#include "mem.h"
#include "workq.h"


/**
 * the "stateChanged" event, as documented in <a
 * href='../../events.rst'>Events</a>
 */
#define JW_STATES_EVENT "stateChanged"

/**
 * helper macro for stringifying state enum symbols, for use, for example, in
 * populating the 'names' parameter for the constructor
 */
#define JW_STATES_NAME(num) #num


/** typedef for an index in the list of states */
typedef uint8_t jw_state_val;

/** an instance of a states object */
typedef struct _jw_states jw_states;

/**
 * an instance of the object referenced by the data member of the jw_event_data
 * argument sent to the stateChanged event callback(s)
 */
typedef struct _jw_states_event_data jw_states_event_data;


#ifdef __cplusplus
extern "C"
{
#endif

/**
 * Creates a states object.
 *
 * The length of the names array determines the number of states that this
 * object will manage.  The state numbers correspond to the indices of their
 * names/descriptions in the names array.  The names themselves can be retrieved
 * later via the jw_states_get_name_for() function.  The names are not required
 * to be unique, although it is often convenient to make them so.
 *
 * This function can generate the following errors (set when returning false):
 * \li \c JW_ERR_INVALID_ARG if initial does not indicate a valid index in names
 *   or if names has too many elements to be represented by the jw_state_val
 *   type
 * \li \c JW_ERR_NO_MEMORY if there is insufficient memory to initialize the
 *   states object
 *
 * \invariant names != NULL
 * \invariant workq != NULL
 * \invariant states != NULL
 * \param[in] initial the initial state
 * \param[in] names a NULL-terminated array of strings.  Each name in names is
 *   duplicated into the new states object; the caller can release the memory
 *   for names once this function returns.
 * \param[in] workq the workq to use for triggering events asynchronously
 * \param[out] states the newly created states object
 * \param[out] err the error information (provide NULL to ignore)
 * \retval bool true if the states object was created successfully
 */
JABBERWERX_API bool jw_states_create(const char **names,
                                     jw_state_val initial,
                                     jw_workq    *workq,
                                     jw_states  **states,
                                     jw_err      *err);

/**
 * Unbinds all bound events and destroys the states object.
 *
 * Note that no events or opaque pointers (such as those passed in as "arg" or
 * "extra" parameters) that have been passed into the object are destroyed.
 *
 * \invariant states != NULL
 * \param[in] states the states object to destroy
 */
JABBERWERX_API void jw_states_destroy(jw_states *states);

/**
 * Retrieves the current state.
 *
 * \b NOTE: This method should not be called from a state transition event
 * callback since its value may be misleading if multiple state transitions were
 * initiated in quick succession.  The jw_states_event_data_get_prev() and
 * _get_next() functions are provided for determining what the current and
 * next states were at the time of the transition.
 *
 * \invariant states != NULL
 * \param[in] states the states object
 * \retval jw_state_val the current state
 */
JABBERWERX_API jw_state_val jw_states_get_current(jw_states *states);

/**
 * Retrieves the name for the given state.
 *
 * The returned string is owned by the states object and must not be freed by
 * the caller.
 *
 * \invariant states != NULL
 * \param[in] states the states object
 * \param[in] state_val the target state
 * \retval const char * the state name/description that was passed to the
 *   constructor or NULL if the state is unknown
 */
JABBERWERX_API const char * jw_states_get_name_for(jw_states   *states,
                                                   jw_state_val state_val);

/**
 * Registers a callback to be bound to an event while this object is in a
 * specific state.
 *
 * When this states object transitions from another state to current, it will
 * call jw_event_bind(evt, cb, arg, err) for the specified arguments.  When it
 * transitions from current to another state, it will call
 * jw_event_unbind(evt, cb).  Note that, depending on which events are shared
 * among states, the final order in which the callbacks are called for a
 * specific event may change during a state transition.
 *
 * If the states object is already in the specified state, the callback is bound
 * to its event immediately.
 *
 * NOTE: no attempt is made to ensure that the evt/cb combination is unique in
 * the registration list.  If duplicates are registered, the most-recently
 * registered evt/cb combination will "win".  Any previous entries will just
 * take up memory and CPU time.
 *
 * This function can generate the following errors (set when returning false):
 * \li \c JW_ERR_INVALID_ARG if current does not specify a known state
 * \li \c JW_ERR_NO_MEMORY if there is insufficient memory to complete the
 *   operation
 *
 * \invariant states != NULL
 * \invariant evt != NULL
 * \invariant cb != NULL
 * \param[in] states the states object
 * \param[in] current the target state
 * \param[in] evt the target event
 * \param[in] cb the callback to bind to the event
 * \param[in] arg the opaque argument to pass to the callback
 * \param[out] err the error information (provide NULL to ignore)
 * \retval bool true if the callback was registered successfully
 */
JABBERWERX_API bool jw_states_register_for(jw_states               *states,
                                           jw_state_val             current,
                                           jw_event                *evt,
                                           jw_event_notify_callback cb,
                                           void                    *arg,
                                           jw_err                  *err);

/**
 * Changes the current state value for this states object to next.
 *
 * If the current state before this function is called is the same as next, no
 * operations are performed.  Otherwise, this function unbinds the callbacks
 * registered for the current state, binds all of the callbacks registered for
 * next, then triggers the "stateChanged" event.
 *
 * This function can generate the following errors (set when returning false):
 * \li \c JW_ERR_INVALID_ARG if current does not specify a known state
 * \li \c JW_ERR_NO_MEMORY if there is insufficient memory to complete the
 *   operation
 *
 * \invariant states != NULL
 * \param[in] states the states object
 * \param[in] next the target state
 * \param[in] extra the opaque pointer to include in the stateChanged event data
 * \param[in] extra_cleaner the cleaner function for the extra parameter
 * \param[out] err the error information (provide NULL to ignore)
 * \retval bool true if the state was changed successfully
 */
JABBERWERX_API bool jw_states_change(jw_states        *states,
                                     jw_state_val      next,
                                     void             *extra,
                                     jw_data_free_func extra_cleaner,
                                     jw_err           *err);

/**
 * Get the event that is triggered whenever a state transition occurs.
 *
 * The memory allocated for the returned event is owned by the states object.
 *
 * \invariant states != NULL
 * \invariant name != NULL
 * \invariant *name != '\\0'
 * \param[in] states the states object
 * \param[in] name The name of the event.  For this module, the only valid
 *   event name is JW_STATES_EVENT ("stateChanged").
 * \retval jw_event rhe found event or NULL if it does not exist
 */
JABBERWERX_API jw_event *jw_states_event(jw_states *states, const char *name);

/**
 * Retrieves the previous state during a stateChanged event.
 *
 * \invariant event_data != NULL
 * \param[in] event_data the states event data
 * \retval jw_state_val the previous state
 */
JABBERWERX_API jw_state_val jw_states_event_data_get_prev(
        jw_states_event_data *event_data);

/**
 * Retrieves the next state during a stateChanged event.
 *
 * \invariant event_data != NULL
 * \param[in] event_data the states event data
 * \retval jw_state_val the next state
 */
JABBERWERX_API jw_state_val jw_states_event_data_get_next(
        jw_states_event_data *event_data);

/**
 * Retrieves the user-supplied extra data during a stateChanged event.
 *
 * \invariant event_data != NULL
 * \param[in] event_data the states event data
 * \retval void* the extra data passed to the jw_states_change() function
 */
JABBERWERX_API void * jw_states_event_data_get_extra(
        jw_states_event_data *event_data);

#ifdef __cplusplus
}
#endif

#endif  /* JABBERWERX_UTIL_STATES_H */
