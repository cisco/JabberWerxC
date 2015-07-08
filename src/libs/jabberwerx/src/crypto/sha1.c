/**
 *
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

#include "jabberwerx/crypto/sha1.h"
#include "jabberwerx/util/mem.h"
#include "jabberwerx/util/log.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

/* If openssl, use sha1_openssl.c */
#ifdef JABBERWERX_TLS_NONE

/*****************************************************************************
 * Internal type definitions
 */

#define JABBERWERX_SHA1_BLOCK_LENGTH 64
#define JABBERWERX_SHA1_ESTATE 1

#define _SHA1CircularShift(bits,word) \
                (((word) << (bits)) | ((word) >> (32-(bits))))


typedef struct _jw_sha1_ctx_int
{
    uint32_t Intermediate_Hash[JW_SHA1_HASH_SIZE/4];    /* Message Digest  */

    uint32_t Length_Low;                                        /* Message length in bits */
    uint32_t Length_High;                                       /* Message length in bits */

    int_least16_t Message_Block_Index;                          /* Index into message block array*/
    uint8_t Message_Block[JABBERWERX_SHA1_BLOCK_LENGTH];        /* 512-bit message blocks */

    int Computed;                                               /* Is the digest computed? */
    int Corrupted;                                              /* Is the message digest corrupted? */
} jw_sha1_ctx_int;

typedef struct _jw_hmac_sha1_ctx_int
{
    jw_sha1_ctx *inner;
    uint8_t key[JABBERWERX_SHA1_BLOCK_LENGTH];
    bool valid;
} jw_hmac_sha1_ctx_int;

/****************************************************************************
 * Internal functions
 */

static void _SHA1ProcessMessageBlock(jw_sha1_ctx *ctx)
{
    const uint32_t K[] =    {       /* Constants defined in SHA-1   */
                            0x5A827999,
                            0x6ED9EBA1,
                            0x8F1BBCDC,
                            0xCA62C1D6
                            };
    int           t;                 /* Loop counter                */
    uint32_t      temp;              /* Temporary word value        */
    uint32_t      W[80];             /* Word sequence               */
    uint32_t      A, B, C, D, E;     /* Word buffers                */

    /*
     *  Initialize the first 16 words in the array W
     */
    for(t = 0; t < 16; t++)
    {
        W[t] = ctx->Message_Block[t * 4] << 24;
        W[t] |= ctx->Message_Block[t * 4 + 1] << 16;
        W[t] |= ctx->Message_Block[t * 4 + 2] << 8;
        W[t] |= ctx->Message_Block[t * 4 + 3];
    }

    for(t = 16; t < 80; t++)
    {
       W[t] = _SHA1CircularShift(1,W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]);
    }

    A = ctx->Intermediate_Hash[0];
    B = ctx->Intermediate_Hash[1];
    C = ctx->Intermediate_Hash[2];
    D = ctx->Intermediate_Hash[3];
    E = ctx->Intermediate_Hash[4];

    for(t = 0; t < 20; t++)
    {
        temp =  _SHA1CircularShift(5,A) +
                ((B & C) | ((~B) & D)) + E + W[t] + K[0];
        E = D;
        D = C;
        C = _SHA1CircularShift(30,B);

        B = A;
        A = temp;
    }

    for(t = 20; t < 40; t++)
    {
        temp = _SHA1CircularShift(5,A) + (B ^ C ^ D) + E + W[t] + K[1];
        E = D;
        D = C;
        C = _SHA1CircularShift(30,B);
        B = A;
        A = temp;
    }

    for(t = 40; t < 60; t++)
    {
        temp = _SHA1CircularShift(5,A) +
               ((B & C) | (B & D) | (C & D)) + E + W[t] + K[2];
        E = D;
        D = C;
        C = _SHA1CircularShift(30,B);
        B = A;
        A = temp;
    }

    for(t = 60; t < 80; t++)
    {
        temp = _SHA1CircularShift(5,A) + (B ^ C ^ D) + E + W[t] + K[3];
        E = D;
        D = C;
        C = _SHA1CircularShift(30,B);
        B = A;
        A = temp;
    }

    ctx->Intermediate_Hash[0] += A;
    ctx->Intermediate_Hash[1] += B;
    ctx->Intermediate_Hash[2] += C;
    ctx->Intermediate_Hash[3] += D;
    ctx->Intermediate_Hash[4] += E;

    ctx->Message_Block_Index = 0;
}
static void _SHA1PadMessage(jw_sha1_ctx *ctx)
{
    /*
     *  Check to see if the current message block is too small to hold
     *  the initial padding bits and length.  If so, we will pad the
     *  block, process it, and then continue padding into a second
     *  block.
     */
    if (ctx->Message_Block_Index > 55)
    {
        ctx->Message_Block[ctx->Message_Block_Index++] = 0x80;
        while(ctx->Message_Block_Index < JABBERWERX_SHA1_BLOCK_LENGTH)
        {
            ctx->Message_Block[ctx->Message_Block_Index++] = 0;
        }

        _SHA1ProcessMessageBlock(ctx);

        while(ctx->Message_Block_Index < 56)
        {
            ctx->Message_Block[ctx->Message_Block_Index++] = 0;
        }
    }
    else
    {
        ctx->Message_Block[ctx->Message_Block_Index++] = 0x80;
        while(ctx->Message_Block_Index < 56)
        {

            ctx->Message_Block[ctx->Message_Block_Index++] = 0;
        }
    }

    /*
     *  Store the message length as the last 8 octets
     */
    ctx->Message_Block[56] = ctx->Length_High >> 24;
    ctx->Message_Block[57] = ctx->Length_High >> 16;
    ctx->Message_Block[58] = ctx->Length_High >> 8;
    ctx->Message_Block[59] = ctx->Length_High;
    ctx->Message_Block[60] = ctx->Length_Low >> 24;
    ctx->Message_Block[61] = ctx->Length_Low >> 16;
    ctx->Message_Block[62] = ctx->Length_Low >> 8;
    ctx->Message_Block[63] = ctx->Length_Low;

    _SHA1ProcessMessageBlock(ctx);
}

/****************************************************************************
 * EXTERNAL functions
 */

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
    *ctx = jw_sha1_reset(tmp);

    return true;
}

JABBERWERX_API void jw_sha1_destroy(jw_sha1_ctx *ctx)
{
    assert(ctx);

    jw_data_free(ctx);
}

JABBERWERX_API jw_sha1_ctx *jw_sha1_reset(jw_sha1_ctx *ctx)
{
    assert(ctx);

    ctx->Length_Low             = 0;
    ctx->Length_High            = 0;
    ctx->Message_Block_Index    = 0;

    ctx->Intermediate_Hash[0]   = 0x67452301;
    ctx->Intermediate_Hash[1]   = 0xEFCDAB89;
    ctx->Intermediate_Hash[2]   = 0x98BADCFE;
    ctx->Intermediate_Hash[3]   = 0x10325476;
    ctx->Intermediate_Hash[4]   = 0xC3D2E1F0;

    ctx->Computed   = 0;
    ctx->Corrupted  = 0;

    return ctx;
}

JABBERWERX_API bool jw_sha1_input(jw_sha1_ctx *ctx,
                                  const uint8_t *input,
                                  size_t len,
                                  jw_err *err)
{
    if (!len)
    {
        return true;
    }

    assert(ctx);
    assert(input);

    if (ctx->Computed)
    {
        ctx->Corrupted = JABBERWERX_SHA1_ESTATE;
        JABBERWERX_ERROR(err, JW_ERR_INVALID_STATE);
        return false;
    }

    if (ctx->Corrupted)
    {
        JABBERWERX_ERROR(err, JW_ERR_INVALID_STATE);
         return false;
    }

    while(len-- && !ctx->Corrupted)
    {
        ctx->Message_Block[ctx->Message_Block_Index++] =
                        (*input & 0xFF);

        ctx->Length_Low += 8;
        if (ctx->Length_Low == 0)
        {
            ctx->Length_High++;
            if (ctx->Length_High == 0)
            {
                /* Message is too long */
                JABBERWERX_ERROR(err, JW_ERR_INVALID_ARG);
                ctx->Corrupted = 1;
                break;
            }
        }

        if (ctx->Message_Block_Index == JABBERWERX_SHA1_BLOCK_LENGTH)
        {
            _SHA1ProcessMessageBlock(ctx);
        }

        input++;
    }

    return (ctx->Corrupted == 0);
}

JABBERWERX_API bool jw_sha1_result(jw_sha1_ctx *ctx,
                                   uint8_t **output,
                                   size_t *output_len,
                                   jw_err *err)
{
    uint8_t *result;
    int i;

    assert(ctx);
    assert(output);
    assert(output_len);

    if (ctx->Corrupted)
    {
        JABBERWERX_ERROR(err, JW_ERR_INVALID_STATE);
        return false;
    }
    result = (uint8_t*)jw_data_malloc(JW_SHA1_HASH_SIZE);
    if (!result)
    {
        JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
        return false;
    }

    if (!ctx->Computed)
    {
        _SHA1PadMessage(ctx);
        for(i=0; i<JABBERWERX_SHA1_BLOCK_LENGTH; ++i)
        {
            /* message may be sensitive, clear it out */
            ctx->Message_Block[i] = 0;
        }
        ctx->Length_Low = 0;    /* and clear length */
        ctx->Length_High = 0;
        ctx->Computed = 1;

    }

    for(i = 0; i < JW_SHA1_HASH_SIZE; ++i)
    {
        result[i] = ctx->Intermediate_Hash[i>>2] >> 8 * ( 3 - ( i & 0x03 ) );
    }

    *output = result;
    *output_len = JW_SHA1_HASH_SIZE;

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
    memset(tmp, 0, sizeof(struct _jw_hmac_sha1_ctx_int));

    if (!jw_sha1_create(&tmp->inner, err))
    {
        return false;
    }

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
    jw_sha1_destroy(ctx->inner);
    jw_data_free(ctx);
}

JABBERWERX_API bool jw_hmac_sha1_reset(jw_hmac_sha1_ctx *ctx,
                                       const uint8_t *key,
                                       size_t key_len,
                                       jw_err *err)
{
    uint8_t ik[JABBERWERX_SHA1_BLOCK_LENGTH];
    size_t i;

    assert(ctx);
    jw_sha1_reset(ctx->inner);

    if (key && (key_len > 0))
    {
        memset(ctx->key, 0, JABBERWERX_SHA1_BLOCK_LENGTH);
        if (key_len > JABBERWERX_SHA1_BLOCK_LENGTH)
        {
            uint8_t *hash = NULL;
            size_t hash_len = 0;

            if (!jw_sha1(key, key_len, &hash, &hash_len, err))
            {
                return false;
            }
            assert(hash_len < JABBERWERX_SHA1_BLOCK_LENGTH);
            memcpy(ctx->key, hash, hash_len);
            jw_data_free(hash);
        }
        else
        {
            memcpy(ctx->key, key, key_len);
        }
    }

    for (i=0; i<JABBERWERX_SHA1_BLOCK_LENGTH; i++)
    {
        // From RFC 2104, section 2
        // ipad = the byte 0x36 repeated B times
        ik[i] = ctx->key[i] ^ 0x36;
        // opad = the byte 0x5C repeated B times
        ctx->key[i] ^= 0x5c;
    }

    if (!jw_sha1_input(ctx->inner, ik, JABBERWERX_SHA1_BLOCK_LENGTH, err))
    {
        return false;
    }

    ctx->valid = true;
    return true;
}

JABBERWERX_API bool jw_hmac_sha1_input(jw_hmac_sha1_ctx *ctx,
                                       const uint8_t *input,
                                       size_t len,
                                       jw_err *err)
{
    assert(ctx);

    if (!ctx->valid)
    {
        JABBERWERX_ERROR(err, JW_ERR_INVALID_STATE);
        return false;
    }

    // jw_sha1_input will check len, and assert input.
    return jw_sha1_input(ctx->inner, input, len, err);
}

JABBERWERX_API bool jw_hmac_sha1_result(jw_hmac_sha1_ctx *ctx,
                                        uint8_t **output,
                                        size_t *output_len,
                                        jw_err *err)
{
    uint8_t *inner = NULL;
    size_t  inner_len = 0;
    jw_sha1_ctx *outer = NULL;
    bool ret = false;

    assert(ctx);
    assert(output);
    assert(output_len);

    if (!ctx->valid)
    {
        JABBERWERX_ERROR(err, JW_ERR_INVALID_STATE);
        goto _jw_hmac_sha1_result_complete;
    }

    // From RFC 2104, section 2
    // H(K XOR opad, H(K XOR ipad, text))
    //
    // ctx->inner is H(K XOR ipad, text)
    // ctx->key is K XOR opad
    if (!jw_sha1_create(&outer, err) ||
        !jw_sha1_input(outer, ctx->key, JABBERWERX_SHA1_BLOCK_LENGTH, err) ||
        !jw_sha1_result(ctx->inner, &inner, &inner_len, err) ||
        !jw_sha1_input(outer, inner, inner_len, err) ||
        !jw_sha1_result(outer, output, output_len, err))
    {
        goto _jw_hmac_sha1_result_complete;
    }

    ret = true;
_jw_hmac_sha1_result_complete:
    if (inner)
    {
        jw_data_free(inner);
    }

    if (outer)
    {
        jw_sha1_destroy(outer);
    }

    return ret;
}
#endif // JABBERWERX_TLS_NONE

/****************************************************************************
 * Convenience functions
 */
JABBERWERX_API bool jw_sha1(const uint8_t *input,
                            size_t input_len,
                            uint8_t **output,
                            size_t *output_len,
                            jw_err *err)
{
    jw_sha1_ctx *ctx = NULL;
    bool result = true;

    assert(output);
    assert(output_len);

    if (!jw_sha1_create(&ctx, err))
    {
        return false;
    }

    result = jw_sha1_input(ctx, input, input_len, err) &&
        jw_sha1_result(ctx, output, output_len, err);

    jw_sha1_destroy(ctx);

    return result;
}

JABBERWERX_API bool jw_hmac_sha1(const uint8_t *input,
                                 size_t input_len,
                                 const uint8_t *key,
                                 size_t key_len,
                                 uint8_t **output,
                                 size_t *output_len,
                                 jw_err *err)
{
    jw_hmac_sha1_ctx *ctx = NULL;
    bool result = true;

    if (!jw_hmac_sha1_create(key, key_len, &ctx, err))
    {
        return false;
    }

    result = jw_hmac_sha1_input(ctx, input, input_len, err) &&
        jw_hmac_sha1_result(ctx, output, output_len, err);

    jw_hmac_sha1_destroy(ctx);
    return result;
}
