/**
 * \file
 * \brief
 * This file contains JabberWerxC Work Queue types and functions
 *
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

#ifndef JABBERWERX_UTIL_WORKQ_H
#define JABBERWERX_UTIL_WORKQ_H

#include "htable.h"


/**
 * The work queue configuration hash table key for event_base selector.
 * The value for this option MUST be a (struct event_base*)(uintptr_t).
 *
 * NOTE:
 * this key is identical to the stream's selector key.
 */
#define JW_WORKQ_CONFIG_SELECTOR "selector"


/** A work queue reference */
typedef struct jw_workq_t jw_workq;

/** A work queue item reference */
typedef struct jw_workq_item_t jw_workq_item;


/**
 * Signature of the function executed when a jw_workq_item is processed
 * in a jw_workq.
 *
 * \param[in] item The item being executed
 * \param[in] data Data associated with executing item.
 */
typedef void (*jw_workq_func)(jw_workq_item *item, void *data);

/**
 * Signature for a jw_workq_item cleaner.
 *
 * This function is called when the jw_workq_item's data is ready to be
 * released, either because new data has been applied or because the
 * jw_workq_item is being destroyed.
 *
 * \param[in] item The item being cleaned
 * \param[in] data The data to free
 */
typedef void (*jw_workq_item_cleaner)(jw_workq_item *item, void *data);


#ifdef __cplusplus
extern "C"
{
#endif

/**
 * This function calls jw_data_free on the data argument, and ignores item.
 * It is a convenience for cleaning memory allocated via
 * jw_data_malloc/jw_data_realloc.
 *
 * \param[in] item Ignored
 * \param[in] data The reference to be freed
 */
JABBERWERX_API void jw_workq_item_free_data_cleaner(jw_workq_item *item,
                                                    void          *data);

/**
 * A convenience function for destroying jw_pool when working with jw_workq.
 * This function calls jw_pool_destroy on the data argument, and ignores the
 * item.
 *
 * \see jw_workq_item_set_data for more information.
 *
 * \param[in] item Ignored
 * \param[in] data The jw_pool to be destroyed
 */
JABBERWERX_API void jw_workq_item_pool_cleaner(jw_workq_item *item, void *data);

/**
 * This function creates a workq item against a given workq.
 *
 * Item will be destroyed when the given jw_workq is destroyed (unless
 * explicitly destroyed by the creator)
 *
 * NOTE:
 * This function can generate the following errors (set when returning false):
 * \li \c JW_ERR_NO_MEMORY if jw_workq_item instance could not be allocated.
 *
 * \invariant (q != NULL)
 * \invariant (fn != NULL)
 * \invariant (item != NULL)
 * \param[in] q The item's jw_workq
 * \param[in] fn The function to be executed when a scheduled item is dequeued.
 * \param[out] item The newly created item.
 * \param[out] err The error information (provide NULL to ignore)
 * \retval bool Returns true if the item was created, false otherwise.
*/
JABBERWERX_API bool jw_workq_item_create(jw_workq       *q,
                                         jw_workq_func   fn,
                                         jw_workq_item **item,
                                         jw_err         *err);

/**
 * Destroy a jw_workq_item.
 *
 * The item is canceled if it is in its workq but not yet executed.
 * The jw_workq_item_cleaner is called if registered.
 *
 *\invariant (item != NULL)
 *\param[in] item The item to destroy
 */
JABBERWERX_API void jw_workq_item_destroy(jw_workq_item *item);

/**
 * Cancels this workq item.
 *
 * If the workq item has already executed or was never scheduled, this function
 * does nothing. Otherwise, it marks the workq item as canceled, and removes it
 * from the workq. Canceled workq items can be rescheduled.
 *
 * NOTE:
 * This function does NOT destroy the workq_item.
 *
 * \invariant (item != NULL)
 * \param[in] item The item to cancel
 */
JABBERWERX_API void jw_workq_item_cancel(jw_workq_item *item);

/**
 * Add the given workq item to the end of its owning workq, behind
 * any items already queued. The given workq item will be executed after
 * all others currently in the queue.
 *
 * If the workq item has a delay, it will be considered scheduled, but will
 * actually be added to the end of the queue when the delay is reached.
 *
 * NOTE:
 * This function can generate the following errors (set when returning false):
 * \li \c JW_ERR_INVALID_STATE - the workq item is already scheduled
 *
 * \invariant (item != NULL)
 * \param[in] item The item to append to its owning jw_workq
 * \param[out] err The error information (provide NULL to ignore)
 * \retval bool Returns true if successfully enqueued, false otherwise.
 */
JABBERWERX_API bool jw_workq_item_append(jw_workq_item *item, jw_err *err);

/**
 * Add the given workq item to the front of its owning workq. The given
 * workq item will be the next item executed.
 *
 * If the workq item has a delay, it will be considered scheduled, but will
 * actually be added to the front of the queue when the delay is reached.
 *
 * NOTE:
 * This function can generate the following errors (set when returning false):
 * \li \c JW_ERR_INVALID_STATE - the workq item is already scheduled
 *
 * \invariant (item != NULL)
 * \param[in] item The item to prepend to its owning jw_workq
 * \param[out] err The error information (provide NULL to ignore)
 * \retval bool Returns true if successfully enqueued, false otherwise.
 */
JABBERWERX_API bool jw_workq_item_prepend(jw_workq_item *item, jw_err *err);

/**
 * Sets the data and its associated cleaner for the workq item.
 *
 * If there is already data applied, this function will call the cleaner
 * associated with the original data (if any).
 *
 * \invariant (item != NULL)
 * \param[in] item The item to associate with the given data.
 * \param[in] data Optional item specific data.
 * \param[in] cleaner Optional cleaner function
*/
JABBERWERX_API void jw_workq_item_set_data(jw_workq_item        *item,
                                           void                 *data,
                                           jw_workq_item_cleaner cleaner);

/**
 * Get the data associated with this item.
 *
 * \invariant (item != NULL)
 * \param[in] item The item used to get the data reference
 * \retval void* May be NULL if item has no associated data
 */
JABBERWERX_API void *jw_workq_item_get_data(jw_workq_item *item);

/**
 * Sets the execution delay for the workq item.  If msecs is 0, then the workq
 * item will execute as soon as possible after it is scheduled.
 *
 * NOTE:
 * The delay takes effect only at the moment when the workq item is scheduled.
 * Calling this function after the delay is scheduled has no effect.
 *
 * NOTE:
 * This function can generate the following errors (set when returning false):
 * \li \c JW_ERR_NO_MEMORY - memory need to track the delay could not be
 *     allocated
 *
 * \invariant (item != NULL)
 * \param[in] item The item to set the delay on
 * \param[in] msecs The delay (in milliseconds) before this workq item
 *            executes
 * \param[out] err The error information (provide NULL to ignore)
 * \retval bool Returns true if delay is set successfully, false otherwise.
 */
JABBERWERX_API bool jw_workq_item_set_delay(jw_workq_item *item,
                                            uint64_t       msecs,
                                            jw_err        *err);

/**
 * Get the execution delay for the workq item.
 *
 * \invariant (item != NULL)
 * \param[in] item The item to retrieve the delay for
 * \retval uint64_t The delay (in milliseconds) associated with the
 *         workq_item, or 0 if a delay was not set.
 */
JABBERWERX_API uint64_t jw_workq_item_get_delay(jw_workq_item *item);

/**
 * Get the jw_workq associated with this item.
 *
 * \invariant (item != NULL)
 * \param[in] item The item used to get the jw_workq reference
 * \retval jw_workq All items have a jw_workq, result will never be NULL.
 */
JABBERWERX_API jw_workq *jw_workq_item_get_workq(jw_workq_item *item);

/**
 * Is the given item enqueued in its associated workq?
 *
 * Scheduled items are items in the workq. Executing and canceled items are
 * *not* scheduled.
 *
 * \invariant (item != NULL)
 * \param[in] item The item to check
 * \retval bool True if the given item is in its associated jw_workq
 */
JABBERWERX_API bool jw_workq_item_is_scheduled(jw_workq_item *item);

/**
 * Create a work queue
 *
 * This function is passed a jw_htable configuration containing the following:
 *      JW_WORKQ_CONFIG_SELECTOR - The event_base the work queue should use
 *          for eventing.
 *
 * The work queue does not reference the configuration htable after its
 * construction is completed and will not attempt any cleanup of the table.
 *
 * NOTE:
 * Users of the work queue must call event_base_dispatch (or another event
 * loop function) for queued tasks to be executed.
 *
 * NOTE:
 * This function can generate the following errors (set when returning false):
 * \li \c JW_ERR_NO_MEMORY if queue heap references could not be allocated.
 * \li \c JW_ERR_INVALID_ARG if config does not contain JW_WORKQ_CONFIG_SELECTOR
 *
 * \invariant q != NULL
 * \invariant config != NULL
 * \param[in] config A hashtable with queue options
 * \param[out] q The newly created work item queue
 * \param[out] err The error information (provide NULL to ignore)
 * \retval bool Returns true if queue was successfully created, false otherwise.
 */
JABBERWERX_API bool jw_workq_create(jw_htable *config,
                                    jw_workq **q,
                                    jw_err    *err);

/**
 * Destroy the given queue.
 *
 * Task processing is stopped immediately. No queued items will be executed
 * after the queue is destroyed.
 *
 * All jw_workq_items created with this queue are destroyed and their
 * associated data cleaners called as needed.
 *
 * \invariant q != NULL
 * \param[in] q The queue to destroy
 */
JABBERWERX_API void jw_workq_destroy(jw_workq *q);

/**
 * Pause the given queue
 *
 * No currently queued tasks will be executed until a paired
 * jw_workq_resume is called.
 *
 * NOTE:
 * pause and resume are reference counted to avoid nested call problems
 *
 * \invariant q != NULL
 * \param[in] q The queue to pause
 */
JABBERWERX_API void jw_workq_pause(jw_workq *q);

/**
 * Resume processing items on the given queue
 *
 * Queue processing will begin again as soon as possible.
 *
 * NOTE:
 * pause and resume are reference counted to avoid nested call problems
 *
 * \invariant q != NULL
 * \param[in] q The queue to resume
 */
JABBERWERX_API void jw_workq_resume(jw_workq *q);

/**
 * Get the number of scheduled tasks in the given queue
 *
 * \invariant q != NULL
 * \param[in] q The queue to count entries from
 * \retval size_t The number of jw_work_item(s) in the given queue
 */
JABBERWERX_API size_t jw_workq_get_length(jw_workq *q);

/**
 * Check if the given queue is empty, no scheduled items
 *
 * \invariant q != NULL
 * \param[in] q The specified queue
 * \retval bool
 */
JABBERWERX_API bool jw_workq_is_empty(jw_workq *q);

/**
 * Get the event base selector used by the given queue
 *
 * \invariant q != NULL
 * \param[in] q The specified queue
 * \retval struct event_base* The libevent event_base selector this queue
 *                            is using for eventing.
 */
JABBERWERX_API struct event_base *jw_workq_get_selector(jw_workq *q);

#ifdef __cplusplus
}
#endif

#endif  /* JABBERWERX_UTIL_WORKQ_H */
