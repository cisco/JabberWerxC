/**
 * \file
 * \brief
 * The SASL mechanism factory.  Clients can use the factory to prioritize a list
 * of SASL mechanisms.  When the time comes to choose an appropriate mechanism,
 * the client can submit a list of choices.  The factory will return the highest
 * priority registered mechanism that also appears in the list of choices.
 *
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */


#ifndef JABBERWERX_SASL_FACTORY_H
#define JABBERWERX_SASL_FACTORY_H

#include "sasl_mech.h"


/** A SASL mechanism factory instance */
typedef struct _jw_sasl_factory jw_sasl_factory;

/**
 * Datatype used for iterating through the SASL mechanisms registered with a
 * particular SASL factory.
 */
typedef jw_sasl_mech *jw_sasl_factory_iter;


#ifdef __cplusplus
extern "C"
{
#endif

/**
 * Create a SASL mechanism factory.
 *
 * This function can generate the following errors (set when returning false):
 * \li \c JW_ERR_NO_MEMORY if the factory could not be allocated
 *
 * \invariant NULL != factory
 * \param[in] config A collection of configuration options.  No options are
 *              currently defined for jw_sasl_factory_create.  For the time
 *              being, this parameter can be NULL.
 * \param[out] factory the newly-created factory
 * \param[out] err the error information (provide NULL to ignore)
 * \retval bool true if the factory was created successfully
 */
JABBERWERX_API bool jw_sasl_factory_create(jw_htable        *config,
                                           jw_sasl_factory **factory,
                                           jw_err           *err);

/**
 * Destroy a SASL mechanism factory.
 *
 * \b NOTE: This function does not destroy the config passed to create(), but it
 * does destroy the mechanisms passed to add_mech().
 *
 * \invariant NULL != factory
 * \param[in] factory The factory to clean up
 */
JABBERWERX_API void jw_sasl_factory_destroy(jw_sasl_factory *factory);

/**
 * Calls jw_sasl_factory_destroy on data associated with a jw_htable node.
 * This can be used to clean up a sasl factory when the keys are static values.
 *
 * \param[in] replace ignored
 * \param[in] destroy_key ignored
 * \param[in] key ignored
 * \param[in] data the sasl factory that will be destroyed
 */
JABBERWERX_API void jw_sasl_factory_htable_cleaner(bool  replace,
                                                   bool  destroy_key,
                                                   void *key,
                                                   void *data);

/**
 * Register a SASL mechanism with the factory.  The mechanism becomes the new
 * preferred mechanism for the factory.  The factory takes ownership of the
 * mechanism and will destroy it when the factory is destroyed.  This means that
 * a jw_sasl_mech MUST NOT be added to more than one factory.  If a mechanism
 * needs to be added to more than one factory, duplicate the mechanism with
 * jw_sasl_mech_create() or jw_sasl_mech_copy().
 *
 * This function can generate the following errors (set when returning false):
 * \li \c JW_ERR_NO_MEMORY if the operation failed due to insufficient memory
 * \li \c JW_ERR_INVALID_ARG if a mechanism with the same name is already
 *              registered
 *
 * \invariant NULL != factory
 * \invariant NULL != mech
 * \param[in] factory the SASL mechanism factory
 * \param[in] mech the mechanism to register
 * \param[out] err the error information (provide NULL to ignore)
 * \retval bool true if the mechanism was successfully registered
 */
JABBERWERX_API bool jw_sasl_factory_add_mech(jw_sasl_factory *factory,
                                             jw_sasl_mech    *mech,
                                             jw_err          *err);

/**
 * Parses a mechanism(s) dom and returns an instance of the most preferred
 * mechanism that is both listed in the dom and that can be instantiated given
 * the specified config.
 *
 * The choices dom can be either in the form of a &lt;mechanism/&gt; element or
 * a &lt;mechanisms/&gt; element that contains multiple &lt;mechanism/&gt;
 * elements.  The namespace of the elements is ignored.
 *
 * This function can generate the following errors (set when returning false):
 * \li \c JW_ERR_NO_MEMORY if the operation failed due to insufficient memory
 * \li \c JW_ERR_INVALID_ARG if the given dom does not contain mechanism data
 *
 * \invariant NULL != factory
 * \invariant NULL != choices
 * \invariant NULL != instance
 * \param[in] factory the SASL mechanism factory
 * \param[in] choices the dom that lists the available mechanisms
 * \param[in] config A collection of configuration options that are passed
 *              through to the mechanism's instance constructor.  This function
 *              does not require the parameter to be non-NULL, but the
 *              mechanism's instance constructor might.
 * \param[out] instance The highest-priority mechanism that is listed in
 *              choices and that successfully instantiates, or NULL if no valid
 *              mechanism is found.  If this variable is not NULL when the
 *              function returns, the caller is expected to destroy the instance
 *              when done with it.
 * \param[out] err the error information (provide NULL to ignore)
 * \retval bool true if the mechanisms were successfully extracted from choices
 */
JABBERWERX_API bool jw_sasl_factory_get_best_mech_in_dom(
                        jw_sasl_factory        *factory,
                        jw_dom_node            *choices,
                        jw_htable              *config,
                        jw_sasl_mech_instance **instance,
                        jw_err                 *err);

/**
 * Returns the most preferred mechanism that exists in the specified set.
 *
 * \b NOTE: The choices parameter must have a case-insensitive string-based hash
 * function and a case-insensitive string comparator.
 *
 * This function can generate the following errors (set when returning false):
 * \li \c JW_ERR_NO_MEMORY if the operation failed due to insufficient memory
 *
 * If an error occurs while instantiating a mechanism, the error is ignored and
 * not returned from this function if it is anything other than NO_MEMORY.
 *
 * \invariant NULL != factory
 * \invariant NULL != choices
 * \invariant NULL != mech
 * \param[in] factory the SASL mechanism factory
 * \param[in] choices the set of mechanism names to choose from
 * \param[in] config A collection of configuration options that are passed
 *              through to the mechanism's instance constructor.  This function
 *              does not require the parameter to be non-NULL, but the
 *              mechanism's instance constructor might.
 * \param[out] instance The highest-priority mechanism that is listed in
 *              choices and that successfully instantiates, or NULL if no valid
 *              mechanism is found.  If this variable is not NULL when the
 *              function returns, the caller is expected to destroy the instance
 *              when done with it.
 * \param[out] err the error information (provide NULL to ignore)
 * \retval bool true if there was sufficient memory for this operation
 */
JABBERWERX_API bool jw_sasl_factory_get_best_mech_in_set(
                        jw_sasl_factory        *factory,
                        jw_htable              *choices,
                        jw_htable              *config,
                        jw_sasl_mech_instance **instance,
                        jw_err                 *err);

/**
 * Initializes an iterator to point to the highest-priority mechanism registered
 * in the factory.  If any mechanisms are added to the factory after this
 * iterator is initialized, they will not be visited by this iterator.
 *
 * This function can generate the following errors (set when returning false):
 * \li no errors are defined for this function
 *
 * \invariant NULL != factory
 * \invariant NULL != iter
 * \param[in] factory the SASL mechanism factory
 * \param[out] iter
 * \param[out] err the error information (provide NULL to ignore)
 * \retval bool this function always returns true
 */
JABBERWERX_API bool jw_sasl_factory_iter_begin(jw_sasl_factory      *factory,
                                               jw_sasl_factory_iter *iter,
                                               jw_err               *err);

/**
 * Get the next-highest-priority mechanism registered in the factory.
 *
 * This function can generate the following errors (set when returning false):
 * \li no errors are defined for this function
 *
 * \invariant NULL != iter
 * \invariant NULL != mech
 * \param[in] iter the iterator.  This parameter is both read and modified.
 * \param[out] mech the next item in the collection, or NULL if no more exist
 * \param[out] err the error information (provide NULL to ignore)
 * \retval bool this function always returns true
 */
JABBERWERX_API bool jw_sasl_factory_iter_next(jw_sasl_factory_iter *iter,
                                              jw_sasl_mech        **mech,
                                              jw_err               *err);

#ifdef __cplusplus
}
#endif

#endif	/* JABBERWERX_SASL_FACTORY_H */
