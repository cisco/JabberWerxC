/**
 * \file
 * \brief
 * SASL mechanism types and functions.  A SASL mechanism is an implementation
 * specification for a particular authentication mechanism.  To perform the
 * authentication, a mechanism instance needs to be instantiated and have its
 * evaluate method called one or more times with appropriate data and a
 * completion callback, which will be called by the mechanism to indicate
 * the results of the authentication sequence.
 *
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */


#ifndef JABBERWERX_SASL_MECH_H
#define JABBERWERX_SASL_MECH_H

#include "util/htable.h"
#include "dom.h"


/** SASL error codes defined in RFC 6120 (section 6.5) */
typedef enum
{
    JW_SASL_ERR_NONE                   =  0,
    JW_SASL_ERR_ABORTED                =  1,
    JW_SASL_ERR_ACCOUNT_DISABLED       =  2,
    JW_SASL_ERR_CREDENTIALS_EXPIRED    =  3,
    JW_SASL_ERR_ENCRYPTION_REQUIRED    =  4,
    JW_SASL_ERR_INCORRECT_ENCODING     =  5,
    JW_SASL_ERR_INVALID_AUTHZID        =  6,
    JW_SASL_ERR_INVALID_MECHANISM      =  7,
    JW_SASL_ERR_MALFORMED_REQUEST      =  8,
    JW_SASL_ERR_MECHANISM_TOO_WEAK     =  9,
    JW_SASL_ERR_NOT_AUTHORIZED         = 10,
    JW_SASL_ERR_TEMPORARY_AUTH_FAILURE = 11
} jw_sasl_error;

/** A SASL mechanism implementation specification */
typedef struct _jw_sasl_mech jw_sasl_mech;

/** An instance of a SASL mechanism implementation specification */
typedef struct _jw_sasl_mech_instance jw_sasl_mech_instance;

/**
 * Function called when a mechanism instance is created.  Implementors of this
 * function MUST NOT take ownership of the config object.
 *
 * If returning false, implementors must set err to an appropriate value.
 *
 * \invariant NULL != instance
 * \param[in] instance the mechanism instance
 * \param[in] config A collection of configuration options.  This config table
 *              may be shared with other objects, so any elements that a
 *              mechanism uses or adds should have names with a unique prefix.
 * \param[out] err the error information (provide NULL to ignore)
 * \retval bool true if the mechanism was initialized successfully
 */
typedef bool (*jw_sasl_mech_init_fn)(
                        jw_sasl_mech_instance *instance,
                        jw_htable             *config,
                        jw_err                *err);

/**
 * Function called when a mechanism instance is destroyed.  If the mechanism
 * has allocated any memory and stored it via jw_sasl_mech_instance_set_data(),
 * this is the place to clean it up.
 *
 * \invariant NULL != instance
 * \param[in] instance the mechanism instance
 */
typedef void (*jw_sasl_mech_clean_fn)(jw_sasl_mech_instance *instance);

/**
 * Callback function called by the sasl framework when data evaluation is
 * complete.  The implementor of this function must not destroy the context of
 * out_auth_node unless, of course, jw_dom_context_retain() is also called.
 *
 * \invariant NULL != instance
 * \param[in] instance the mechanism instance
 * \param[in] out_auth_node The node to send to the remote endpoint.  May be
 *              NULL.
 * \param[in] done true if the authentication sequence is complete or has
 *              encountered an unrecoverable error
 * \param[in] sasl_err the SASL error code (JW_SASL_ERR_NONE on success)
 * \param[in] arg the user-provided argument to jw_sasl_instance_evaluate()
 */
typedef void (*jw_sasl_mech_evaluate_complete_fn)(
                        jw_sasl_mech_instance *instance,
                        jw_dom_node           *out_auth_node,
                        bool                   done,
                        jw_sasl_error          sasl_err,
                        void                  *arg);

/**
 * Callback function called by the mechanism when data evaluation is complete.
 * The implementor of this function must take ownership of the out parameter and
 * free it after it has been processed.
 *
 * \invariant NULL != instance
 * \param[in] instance the mechanism instance
 * \param[in] out The bytes produced by the mechanism to be sent to the remote
 *              endpoint.  The encoding of the bytes is mechanism-specific.
 *              May be NULL.  If not NULL, it will be freed with jw_data_free().
 * \param[in] out_len The number of bytes pointed to by out.  If out is NULL,
 *              this must be 0.
 * \param[in] needs_base64_encoding true if out needs to be base64-encoded
 *              before transport
 * \param[in] done true if the authentication sequence is complete or has
 *              encountered an unrecoverable error
 * \param[in] sasl_err the SASL error code (JW_SASL_ERR_NONE on success)
 */
typedef void (*jw_sasl_mech_cdata_evaluate_complete_fn)(
                        jw_sasl_mech_instance *instance,
                        uint8_t               *out,
                        size_t                 out_len,
                        bool                   needs_base64_encoding,
                        bool                   done,
                        jw_sasl_error          sasl_err);

/**
 * Function called to submit data for evaluation by the mechanism.  The
 * implementor of this function must take ownership of the in parameter and free
 * it after it has been processed.
 *
 * If returning false, implementors must set err to an appropriate value.
 *
 * \invariant NULL != instance
 * \invariant NULL != cb
 * \param[in] instance the mechanism instance
 * \param[in] in The bytes submitted to the mechanism.  The encoding of the
 *              bytes is mechanism-specific, but will be base64-decoded and
 *              NULL-terminated.  May be NULL.  If not NULL, it will be freed
 *              with jw_data_free() when this function returns true.
 * \param[in] in_len The number of bytes pointed to by in.  If in is NULL,
 *              this must be 0.
 * \param[in] cdata_cb the data evaluation completion callback
 * \param[out] err the error information (provide NULL to ignore)
 * \retval bool true if the completion callback is guaranteed to execute
 */
typedef bool (*jw_sasl_mech_cdata_evaluate_fn)(
                        jw_sasl_mech_instance                  *instance,
                        uint8_t                                *in,
                        size_t                                  in_len,
                        jw_sasl_mech_cdata_evaluate_complete_fn cb,
                        jw_err                                 *err);

/** Mechanism implementation function table */
typedef struct _jw_sasl_mech_fn_table
{
    /** If non-NULL, called on instantiation */
    jw_sasl_mech_init_fn init_fn;
    /** if non-NULL, called on destruction */
    jw_sasl_mech_clean_fn clean_fn;
    /** called on first call to evaluate() */
    jw_sasl_mech_cdata_evaluate_fn evaluate_start_fn;
    /**
     * if non-NULL, called on subsequent calls to evaluate().  if NULL, a
     * default step_fn will be called that returns a sasl_error to the callback
     */
    jw_sasl_mech_cdata_evaluate_fn evaluate_step_fn;
} jw_sasl_mech_fn_table;


#ifdef __cplusplus
extern "C"
{
#endif

/**
 * Create a SASL mechanism implementation specification.
 *
 * Requirements for SASL mechanism names are specified in RFC 4422, section 3.1:
 *
 *   SASL mechanisms are named by character strings, from 1 to 20
 *   characters in length, consisting of ASCII [ASCII] uppercase letters,
 *   digits, hyphens, and/or underscores.
 *
 * This function can generate the following errors (set when returning false):
 * \li \c JW_ERR_NO_MEMORY if the mechanism could not be allocated.
 * \li \c JW_ERR_INVALID_ARG if name is badly formed or if
 *              fn_table->evaluate_start_fn is NULL.
 *
 * \invariant NULL != name
 * \invariant NULL != fn_table
 * \invariant NULL != mech
 * \param[in] name the mechanism name.  This pointer is stored and used
 *              internally over the lifetime of the mechanism, and so must not
 *              be changed after being submitted here.  It is not freed when the
 *              mechanism is destroyed.  The suggested pattern here is to pass
 *              in a static string.
 * \param[in] fn_table the mechanism implementation function table
 * \param[out] mech the newly-created mechanism
 * \param[out] err the error information (provide NULL to ignore)
 * \retval bool true if the mechanism was created successfully
 */
JABBERWERX_API bool jw_sasl_mech_create(
                        const char            *name,
                        jw_sasl_mech_fn_table *fn_table,
                        jw_sasl_mech         **mech,
                        jw_err                *err);

/**
 * Create a default SASL PLAIN mechanism implementation specification.
 *
 * This function can generate the following errors (set when returning false):
 * \li \c JW_ERR_NO_MEMORY if the mechanism could not be allocated.
 *
 * \invariant NULL != mech
 * \param[in] config A collection of configuration options.  No options are
 *              currently defined for jw_sasl_mech_plain_create.  For the time
 *              being, this parameter can be NULL.
 * \param[out] mech the newly-created mechanism
 * \param[out] err the error information (provide NULL to ignore)
 * \retval bool true if the mechanism was created successfully
 */
JABBERWERX_API bool jw_sasl_mech_plain_create(jw_htable     *config,
                                              jw_sasl_mech **mech,
                                              jw_err        *err);

/**
 * Create a default SASL EXTERNAL mechanism implementation specification.
 *
 * This function can generate the following errors (set when returning false):
 * \li \c JW_ERR_NO_MEMORY if the mechanism could not be allocated.
 *
 * \invariant NULL != mech
 * \param[in] config A collection of configuration options.  No options are
 *              currently defined for jw_sasl_mech_external_create.  For the
 *              time being, this parameter can be NULL.
 * \param[out] mech the newly-created mechanism
 * \param[out] err the error information (provide NULL to ignore)
 * \retval bool true if the mechanism was created successfully
 */
JABBERWERX_API bool jw_sasl_mech_external_create(jw_htable     *config,
                                                 jw_sasl_mech **mech,
                                                 jw_err        *err);

/**
 * Copy a SASL mechanism implementation specification.
 *
 * This function can generate the following errors (set when returning false):
 * \li \c JW_ERR_NO_MEMORY if the mechanism could not be allocated.
 *
 * \invariant NULL != mech
 * \invariant NULL != copy
 * \param[in] mech the mechanism specification to copy
 * \param[out] copy the newly-created mechanism
 * \param[out] err the error information (provide NULL to ignore)
 * \retval bool true if the mechanism was copied successfully
 */
JABBERWERX_API bool jw_sasl_mech_copy(jw_sasl_mech  *mech,
                                      jw_sasl_mech **copy,
                                      jw_err        *err);

/**
 * Destroy a SASL mechanism.
 *
 * \b NOTE: This function does not destroy the config passed to create().
 *
 * \param[in] mech The mechanism to clean up
 */
JABBERWERX_API void jw_sasl_mech_destroy(jw_sasl_mech *mech);

/**
 * Get the name of the given mechanism.
 *
 * \invariant mech != NULL
 * \retval const char* the mechanism name
 */
JABBERWERX_API const char* jw_sasl_mech_get_name(jw_sasl_mech *mech);


/**
 * Create a SASL mechanism instance.
 *
 * For mechanisms managed by a jw_sasl_factory, this function will normally
 * be called by one of the get_best_mech() functions.
 *
 * This function can generate the following errors (set when returning false):
 * \li \c JW_ERR_NO_MEMORY if the mechanism could not be allocated
 * \li any other error that is returned from the mechanism's init_fn
 *
 * \invariant NULL != mech
 * \invariant NULL != instance
 * \param[in] config A collection of configuration options that are passed
 *              through to the mechanism's init_fn.  This function does not
 *              require the parameter to be non-NULL, but the mechanism's
 *              init_fn might.
 * \param[in] mech the mechanism specification to instantiate
 * \param[out] instance the newly-created mechanism instance
 * \param[out] err the error information (provide NULL to ignore)
 * \retval bool true if the mechanism instance was created successfully
 */
JABBERWERX_API bool jw_sasl_mech_instance_create(
                        jw_htable              *config,
                        jw_sasl_mech           *mech,
                        jw_sasl_mech_instance **instance,
                        jw_err                 *err);

/**
 * Destroy a SASL mechanism instance.
 *
 * \b NOTE: This function does not destroy the config passed to create().
 *
 * \invariant NULL != instance
 * \param[in] instance The mechanism instance to clean up
 */
JABBERWERX_API void jw_sasl_mech_instance_destroy(
                        jw_sasl_mech_instance *instance);

/**
 * Submit an authentication node for evaluation by the mechanism.  This function
 * does not take ownership of the submitted node.
 *
 * This function can generate the following errors (set when returning false):
 * \li \c JW_ERR_INVALID_ARG if the give node is not relevant to the SASL
 *      authentication sequence
 * \li \c JW_ERR_INVALID_STATE if the callback from a previous call to this
 *      function has not yet been called
 * \li \c JW_ERR_NO_MEMORY if there is not enough memory to complete this
 *      operation
 * \li any other error that is returned from the mechanism's evaluate_fn
 *
 * Note that if this is not the first call to evaluate and the mechanism's
 * evaluate_step_fn is not defined, a default SASL error will be returned to the
 * completion callback.
 *
 * \invariant NULL != instance
 * \invariant NULL != cb
 * \param[in] instance the mechanism instance
 * \param[in] in_auth_node The node submitted to the mechanism.  The encoding of
 *              any text elements is mechanism-specific.  May be NULL, such as
 *              when the client is sending the initial authentication request.
 * \param[in] cb the completion callback
 * \param[in] arg the opaque argument that will be passed to cb
 * \param[out] err the error information (provide NULL to ignore)
 * \retval bool true if the completion callback is guaranteed to execute
 */
JABBERWERX_API bool jw_sasl_mech_instance_evaluate(
                        jw_sasl_mech_instance            *instance,
                        jw_dom_node                      *in_auth_node,
                        jw_sasl_mech_evaluate_complete_fn cb,
                        void                             *arg,
                        jw_err                           *err);

/**
 * Gets the mechanism specification for this instance.
 *
 * \invariant NULL != instance
 * \param[in] instance the mechanism instance
 * \retval jw_sasl_mech the mechanism specification
 */
JABBERWERX_API jw_sasl_mech *jw_sasl_mech_instance_get_mech(
                        jw_sasl_mech_instance *instance);

/**
 * Sets an opaque data blob.  This function is intended for use only by the
 * mechanism implementation, which can use it to store state.
 *
 * \invariant NULL != instance
 * \param[in] instance the mechanism instance
 * \param[in] data the opaque data blob
 */
JABBERWERX_API void jw_sasl_mech_instance_set_data(
                        jw_sasl_mech_instance *instance, void *data);

/**
 * Gets the opaque data blob.
 *
 * \invariant NULL != instance
 * \param[in] instance the mechanism instance
 * \retval void* the opaque data blob
 */
JABBERWERX_API void* jw_sasl_mech_instance_get_data(
                        jw_sasl_mech_instance *instance);

#ifdef __cplusplus
}
#endif

#endif /* JABBERWERX_SASL_MECH_H */
