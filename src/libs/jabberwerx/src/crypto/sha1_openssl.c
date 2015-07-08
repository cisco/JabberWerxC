/**
 * \file
 *
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

/* Build openssl by default */

#include "jabberwerx/crypto/sha1.h"
#include "jabberwerx/util/mem.h"
#include "jabberwerx/util/log.h"

#include <assert.h>
#include <stdlib.h>

// TODO: when we support non-openssl TLS, we'll need some #ifdef openssl stuff here
#ifndef JABBERWERX_TLS_NONE

#include <openssl/evp.h>
#include <openssl/hmac.h>

typedef struct _jw_sha1_ctx_int
{
    bool valid; // just added to make the unit tests continue to pass.
                // Provides a very small guard against misuse, since the OpenSSL
                // lib can't be bothered to check its inputs.
    EVP_MD_CTX md;
} jw_sha1_ctx_int;

typedef struct _jw_hmac_sha1_ctx_int
{
    bool valid; // just added to make the unit tests continue to pass.
                // Provides a very small guard against misuse, since the OpenSSL
                // lib can't be bothered to check its inputs.
    HMAC_CTX hmac;
} jw_hmac_sha1_ctx_int;

JABBERWERX_API bool jw_sha1_create(jw_sha1_ctx **ctx,
                                   jw_err *err)
{
    assert(ctx);
    jw_sha1_ctx *tmp;
    tmp = (jw_sha1_ctx*)jw_data_malloc(sizeof(struct _jw_sha1_ctx_int));
    if (!tmp)
    {
        JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
        return false;
    }
    // just does a memset0
    EVP_MD_CTX_init(&tmp->md);

    *ctx = jw_sha1_reset(tmp);

    return true;
}

JABBERWERX_API void jw_sha1_destroy(jw_sha1_ctx *ctx)
{
    assert(ctx);
    ctx->valid = false;
    // more or less a no-op for SHA1
    EVP_MD_CTX_cleanup(&ctx->md);
    jw_data_free(ctx);
}

JABBERWERX_API jw_sha1_ctx *jw_sha1_reset(jw_sha1_ctx *ctx)
{
    assert(ctx);
    /* reset to the initial props.  Could in theory error if there's an
       SSL engine involved, but that's going to be a pretty awful misconfig. */
    if (!EVP_DigestInit_ex(&ctx->md, EVP_sha1(), NULL))
    {
        jw_log(JW_LOG_ERROR, "Error in EVP_DigestInit_ex.  Check OpenSSL config.");
        return NULL;
    }
    ctx->valid = true;
    return ctx;
}

JABBERWERX_API bool jw_sha1_input(jw_sha1_ctx *ctx,
                                  const uint8_t *input,
                                  size_t len,
                                  jw_err *err)
{
    assert(ctx);

    if (!len)
    {
        return true;
    }

    assert(input);
    if (!ctx->valid)
    {
        JABBERWERX_ERROR(err, JW_ERR_INVALID_STATE);
        return false;
    }
    if (!EVP_DigestUpdate(&ctx->md, input, len))
    {
        /* Impossible, if I'm reading the OpenSSL code correctly. */
        JABBERWERX_ERROR(err, JW_ERR_INVALID_STATE);
        return false;
    }
    return true;
}

JABBERWERX_API bool jw_sha1_result(jw_sha1_ctx *ctx,
                                   uint8_t **output,
                                   size_t *output_len,
                                   jw_err *err)
{
    uint8_t *result;
    unsigned int result_len = 0;

    assert(ctx);
    assert(output);
    assert(output_len);

    if (!ctx->valid)
    {
        JABBERWERX_ERROR(err, JW_ERR_INVALID_STATE);
        return false;
    }

    result = (uint8_t*)jw_data_malloc(EVP_MAX_MD_SIZE);
    if (!result)
    {
        JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
        return false;
    }
    if (!EVP_DigestFinal_ex(&ctx->md, result, &result_len))
    {
        // Should be impossible.
        JABBERWERX_ERROR(err, JW_ERR_INVALID_STATE);
        return false;
    }

    ctx->valid = false;
    *output_len = result_len;
    *output = result;
    return true;
}

JABBERWERX_API bool jw_hmac_sha1_create(const uint8_t *key,
                                        size_t key_len,
                                        jw_hmac_sha1_ctx **ctx,
                                        jw_err *err)
{
    assert(ctx);
    jw_hmac_sha1_ctx *tmp = (jw_hmac_sha1_ctx*)jw_data_malloc(sizeof(struct _jw_hmac_sha1_ctx_int));
    if (!tmp)
    {
        JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
        return false;
    }
    HMAC_CTX_init(&tmp->hmac);

    if (!jw_hmac_sha1_reset(tmp, key, key_len, err))
    {
        return false;
    }

    *ctx = tmp;
    return true;
}

JABBERWERX_API void jw_hmac_sha1_destroy(jw_hmac_sha1_ctx *ctx)
{
    assert(ctx);
    ctx->valid = false;
    // more or less a no-op for SHA1
    HMAC_CTX_cleanup(&ctx->hmac);
    jw_data_free(ctx);
}

JABBERWERX_API bool jw_hmac_sha1_reset(jw_hmac_sha1_ctx *ctx,
                                       const uint8_t *key,
                                       size_t key_len,
                                       jw_err *err)
{
    UNUSED_PARAM(err);
    assert(ctx);
    /* reset to the initial props.  Could in theory error if there's an
       SSL engine involved, but that's going to be a pretty awful misconfig. */
    /* also: some versions of openssl return an int, some return void.
       Let's just ignore the error for now to avoid a warning. */
    (void)HMAC_Init_ex(&ctx->hmac, key, key_len, EVP_sha1(), NULL);

    ctx->valid = true;
    return true;
}

JABBERWERX_API bool jw_hmac_sha1_input(jw_hmac_sha1_ctx *ctx,
                                       const uint8_t *input,
                                       size_t len,
                                       jw_err *err)
{
    assert(ctx);
    if (!len)
    {
        return true;
    }

    assert(input);
    if (!ctx->valid)
    {
        JABBERWERX_ERROR(err, JW_ERR_INVALID_STATE);
        return false;
    }

    // Some versions return void, some int.  Shouldn't be able to fail, anyway.
    (void)HMAC_Update(&ctx->hmac, input, len);
    return true;
}

JABBERWERX_API bool jw_hmac_sha1_result(jw_hmac_sha1_ctx *ctx,
                                        uint8_t **output,
                                        size_t *output_len,
                                        jw_err *err)
{
    uint8_t *result;
    unsigned int result_len = 0;

    assert(ctx);
    assert(output);
    assert(output_len);

    if (!ctx->valid)
    {
        JABBERWERX_ERROR(err, JW_ERR_INVALID_STATE);
        return false;
    }

    result = (uint8_t*)jw_data_malloc(EVP_MAX_MD_SIZE);
    if (!result)
    {
        JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
        return false;
    }

    // Some versions return void, some int.  Error should be impossible anyway.
    HMAC_Final(&ctx->hmac, result, &result_len);

    ctx->valid = false;
    *output_len = result_len;
    *output = result;
    return true;
}

#endif /* JABBERWERX_TLS_NONE */
