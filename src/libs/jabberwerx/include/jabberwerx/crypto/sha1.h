/**
 * \file
 * \brief
 * Datatypes and functions for computing SHA1 message digests.
 *
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

#ifndef JABBERWERX_CRYPTO_SHA1_H
#define JABBERWERX_CRYPTO_SHA1_H

#include "../basics.h"


/** The size of a computed SHA1 digest, in bytes */
#define JW_SHA1_HASH_SIZE 20


/** An instance of a SHA1 context */
typedef struct _jw_sha1_ctx_int jw_sha1_ctx;

/** An instance of a HMAC SHA1 context */
typedef struct _jw_hmac_sha1_ctx_int jw_hmac_sha1_ctx;


#ifdef __cplusplus
extern "C"
{
#endif

/**
 * Calculates a SHA1 digest with the given input, placing the
 * result into the given output buffer. This function is a convenience
 * for the following:
 * \code
 * jw_sha1_ctx  ctx;
 * jw_err       err;
 * jw_sha1_create(&ctx, &err);
 * if (input_len > 0)
 * {
 *     jw_sha1_input(ctx, input, input_len, &err);
 * }
 * jw_sha1_result(ctx, output, output_len, &err);
 * jw_sha1_destroy(ctx);
 * \endcode
 *
 * \b NOTE: This function will allocate the memory needed to store the computed
 * hash, and MUST be released using jw_data_free.
 *
 * This function can generate the following errors (set when returning false):
 * \li \c JW_ERR_NO_MEMORY if the context could not be allocated; or the
 *     output buffer could not be allocated
 * \li \c JW_ERR_INVALID_STATE If ctx is corrupted
 * \li \c JW_ERR_INVALID_ARG If the total input is too large (2^64 - 1
 *     bits)
 *
 * \invariant output != NULL
 * \invariant output_len != NULL
 * \param[in] input The buffer of data to compute a digest for
 * \param[in] input_len The length of input
 * \param[out] output The buffer to hold the computed hash
 * \param[out] output_len The length of the output buffer
 * \param[out] err The error information (provide NULL to ignore)
 * \retval bool true if the hash was computed, false otherwise
 */
JABBERWERX_API bool jw_sha1(const uint8_t *input,
                            size_t         input_len,
                            uint8_t      **output,
                            size_t        *output_len,
                            jw_err        *err);

/**
 * Creates and initializes a new SHA1 context.
 *
 * This function can generate the following errors (set when returning false):
 * \li \c JW_ERR_NO_MEMORY if the context could not be allocated
 *
 * \invariant ctx != NULL
 * \param[out] ctx The pointer to hold the initialized context
 * \param[out] err The error information (provide NULL to ignore)
 * \retval bool true if the context was created, false otherwise
 */
JABBERWERX_API bool jw_sha1_create(jw_sha1_ctx **ctx,
                                   jw_err *err);
/**
 * Destroys a SHA1 context, freeing any memory used.
 *
 * \invariant ctx != NULL
 * \param ctx The SHA1 context to destroy
 */
JABBERWERX_API void jw_sha1_destroy(jw_sha1_ctx *ctx);

/**
 * Resets a SHA1 context.
 *
 * \invariant ctx != NULL
 * \param ctx The SHA1 context to reset
 * \retval jw_sha1_ctx The reset context
 */
JABBERWERX_API jw_sha1_ctx *jw_sha1_reset(jw_sha1_ctx *ctx);

/**
 * Updates the given SHA1 digest with the given input.
 *
 * This function can generate the following errors (set when returning false):
 * \li \c JW_ERR_INVALID_STATE If ctx is corrupted
 * \li \c JW_ERR_INVALID_ARG If the total input is too large (2^64 - 1
 *     bits)
 *
 * \invariant ctx != NULL
 * \invariant input != NULL
 * \param[in] ctx The SHA1 context to update
 * \param[in] input The data used to udpate ctx
 * \param[in] len The length of input.  If 0, input is ignored.
 * \param[out] err The error information (provide NULL to ignore)
 * \retval bool true if successful, false otherwise.
 */
JABBERWERX_API bool jw_sha1_input(jw_sha1_ctx   *ctx,
                                  const uint8_t *input,
                                  size_t         len,
                                  jw_err        *err);

/**
 * Finalizes the given SHA1 context, placing the computed digest into the
 * given output buffer.
 *
 * \b NOTE: This function will allocate the memory needed to store the computed
 * hash, and MUST be released using jw_data_free.
 *
 * This function can generate the following errors (set when returning false):
 * \li \c JW_ERR_NO_MEMORY if the output buffer could not be allocated
 * \li \c JW_ERR_INVALID_STATE If ctx is corrupted
 *
 * \invariant ctx != NULL
 * \invariant output != NULL
 * \invariant output_len != NULL
 * \param[in] ctx The SHA1 context to finalize
 * \param[out] output The buffer to hold the computed hash.
 * \param[out] output_len The length of the output buffe
 * \param[out] err The error information (provide NULL to ignore)
 * \retval bool true if successful, false otherwise
 */
JABBERWERX_API bool jw_sha1_result(jw_sha1_ctx *ctx,
                                   uint8_t    **output,
                                   size_t      *output_len,
                                   jw_err      *err);

/**
 * Calculates a HMAC-SHA1 message authentication code with the given input, placing the
 * result into the given output buffer. This function is a convenience
 * for the following:
 * \code
 * jw_hmac_sha1_ctx  ctx;
 * jw_err       err;
 * jw_hmac_sha1_create(&ctx, key, key_len, &err);
 * if (input_len > 0)
 * {
 *     jw_hmac_sha1_input(ctx, input, input_len, &err);
 * }
 * jw_hmac_sha1_result(ctx, output, output_len, &err);
 * jw_hmac_sha1_destroy(ctx);
 * \endcode
 *
 * \b NOTE: This function will allocate the memory needed to store the computed
 * hash, and MUST be released using jw_data_free.
 *
 * This function can generate the following errors (set when returning false):
 * \li \c JW_ERR_NO_MEMORY if the context could not be allocated; or the
 *     output buffer could not be allocated
 * \li \c JW_ERR_INVALID_STATE If ctx is corrupted
 *
 * \invariant output != NULL
 * \invariant output_len != NULL
 * \param[in] input The buffer of data to compute a digest for
 * \param[in] input_len The length of input in octets
 * \param[in] key The key for the authentication
 * \param[in] key_len The length of the key in octets
 * \param[out] output The buffer to hold the computed hash
 * \param[out] output_len The length of the output buffer in octets
 * \param[out] err The error information (provide NULL to ignore)
 * \retval bool true if the hash was computed, false otherwise
 */
JABBERWERX_API bool jw_hmac_sha1(const uint8_t *input,
                                 size_t         input_len,
                                 const uint8_t *key,
                                 size_t         key_len,
                                 uint8_t      **output,
                                 size_t        *output_len,
                                 jw_err        *err);

/**
 * Creates and initializes a new HMAC-SHA1 context.
 *
 * This function can generate the following errors (set when returning false):
 * \li \c JW_ERR_NO_MEMORY if the context could not be allocated
 *
 * \invariant ctx != NULL
 * \param[in] key The key for the authentication
 * \param[in] key_len The length of the key in octets
 * \param[out] ctx The pointer to hold the initialized context
 * \param[out] err The error information (provide NULL to ignore)
 * \retval bool true if the context was created, false otherwise
 */
JABBERWERX_API bool jw_hmac_sha1_create(const uint8_t     *key,
                                        size_t             key_len,
                                        jw_hmac_sha1_ctx **ctx, 
                                        jw_err            *err);

/**
 * Destroys an HMAC-SHA1 context, freeing any memory used.
 *
 * \invariant ctx != NULL
 * \param[in] ctx The SHA1 context to destroy
 */
JABBERWERX_API void jw_hmac_sha1_destroy(jw_hmac_sha1_ctx *ctx);

/**
 * Resets a HMAC-SHA1 context.
 *
 * \invariant ctx != NULL
 * \param[in] ctx The SHA1 context to reset
 * \param[in] key The key for the authentication.  If NULL, reuses existing key.
 * \param[in] key_len The length of the key in octets.  If 0, reuses existing key.
 * \param[out] err The error information (provide NULL to ignore)
 * \retval bool true if successful, false otherwise.
 */
JABBERWERX_API bool jw_hmac_sha1_reset(jw_hmac_sha1_ctx *ctx, 
                                       const uint8_t    *key,
                                       size_t            key_len,
                                       jw_err           *err);

/**
 * Updates the given HMAC-SHA1 with the given input.
 *
 * This function can generate the following errors (set when returning false):
 * \li \c JW_ERR_INVALID_STATE If ctx is corrupted
 *
 * \invariant ctx != NULL
 * \invariant input != NULL
 * \param[in] ctx The SHA1 context to update
 * \param[in] input The data used to udpate ctx
 * \param[in] len The length of input.  If 0, input is ignored.
 * \param[out] err The error information (provide NULL to ignore)
 * \retval bool true if successful, false otherwise.
 */
JABBERWERX_API bool jw_hmac_sha1_input(jw_hmac_sha1_ctx *ctx,
                                       const uint8_t    *input,
                                       size_t            len,
                                       jw_err           *err);

/**
 * Finalizes the given HMAC-SHA1 context, placing the computed digest into the
 * given output buffer.
 *
 * \b NOTE: This function will allocate the memory needed to store the computed
 * hash, and MUST be released using jw_data_free.
 *
 * This function can generate the following errors (set when returning false):
 * \li \c JW_ERR_NO_MEMORY if the output buffer could not be allocated
 * \li \c JW_ERR_INVALID_STATE If ctx is corrupted
 *
 * \invariant ctx != NULL
 * \invariant output != NULL
 * \invariant output_len != NULL
 * \param[in] ctx The HMAC-SHA1 context to finalize
 * \param[out] output The buffer to hold the computed hash.
 * \param[out] output_len The length of the output buffe
 * \param[out] err The error information (provide NULL to ignore)
 * \retval bool true if successful, false otherwise
 */
JABBERWERX_API bool jw_hmac_sha1_result(jw_hmac_sha1_ctx *ctx,
                                        uint8_t         **output,
                                        size_t           *output_len,
                                        jw_err           *err);

#ifdef __cplusplus
}
#endif

#endif /* JABBERWERX_CRYPTO_SHA1_H */
