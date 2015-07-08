/**
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

#include "fct.h"

#include <jabberwerx/util/mem.h>
#include <jabberwerx/crypto/sha1.h>


#define fct_chk_eq_array(STR, STR_LEN, CHECK, CHECK_LEN)\
    fct_xchk(fctstr_array_eq((STR), (STR_LEN), (CHECK), (CHECK_LEN)),\
          "array equality check: len:%d != len:%d",\
          (STR_LEN), (CHECK_LEN)\
    )

static int fctstr_array_eq(const uint8_t *one,
                           size_t one_len,
                           const uint8_t *two,
                           size_t two_len)
{
    if (one_len != two_len)
    {
        return 0;
    }

    for (size_t idx=0; idx < one_len; idx++)
    {
        if (one[idx] != two[idx])
        {
            return 0;
        }
    }

    return 1;
}

FCTMF_SUITE_BGN(sha1_test)
{
    FCT_TEST_BGN(jw_sha1_createdestroy)
    {
        jw_sha1_ctx *ctx;
        jw_err      err;

        jw_sha1_create(&ctx, &err);
        fct_chk(ctx);

        jw_sha1_destroy(ctx);
    } FCT_TEST_END()

    FCT_TEST_BGN(jw_sha1_compute_steps)
    {
        jw_sha1_ctx *ctx;
        jw_err      err;
        uint8_t *digest;
        uint8_t *input, *result;
        size_t length, digest_len;
        jw_sha1_create(&ctx, &err);

        /* a random string */
        ctx = jw_sha1_reset(ctx);
        fct_chk(ctx);

        input = (uint8_t*)"a test string";
        length = strlen((const char *)input);
        fct_chk(jw_sha1_input(ctx, input, length, &err) == true);

        result = (uint8_t*)"\x2d\xa7\x5d\xa5\xc8\x54\x78\xdf\x42\xdf\x0f\x91\x77\x00\x24\x1e\xd2\x82\xf5\x99";
        fct_chk(jw_sha1_result(ctx, &digest, &digest_len, &err) == true);
        fct_chk_eq_array(digest, digest_len, result, JW_SHA1_HASH_SIZE);
        jw_data_free(digest);

        /* SASL PLAIN */
        ctx = jw_sha1_reset(ctx);
        fct_chk(ctx);

        input = (uint8_t*)"\0username\0password";
        fct_chk(jw_sha1_input(ctx, input, 18, &err) == true);

        result = (uint8_t*)"\x5e\xf0\x59\x8\x28\x39\x11\x52\x5a\x42\xf3\xeb\xc1\x27\x82\x2b\xc1\x24\xa8\x56";
        fct_chk(jw_sha1_result(ctx, &digest, &digest_len, &err) == true);
        fct_chk_eq_array(digest, digest_len, result, JW_SHA1_HASH_SIZE);
        jw_data_free(digest);

        /* empty string */
        ctx = jw_sha1_reset(ctx);
        fct_chk(ctx);

        input = (uint8_t*)"";
        fct_chk(jw_sha1_input(ctx, input, 0, &err) == true);

        result = (uint8_t*)"\xda\x39\xa3\xee\x5e\x6b\x4b\xd\x32\x55\xbf\xef\x95\x60\x18\x90\xaf\xd8\x7\x9";
        fct_chk(jw_sha1_result(ctx, &digest, &digest_len, &err) == true);
        fct_chk_eq_array(digest, digest_len, result, JW_SHA1_HASH_SIZE);
        jw_data_free(digest);

        jw_sha1_destroy(ctx);
    } FCT_TEST_END()

    FCT_TEST_BGN(jw_sha1_compute_simple)
    {
        jw_err err;
        uint8_t *digest;
        uint8_t *input, *result;
        size_t length, digest_len;

        /* a random string */
        input = (uint8_t*)"a test string";
        length = strlen((const char *)input);
        result = (uint8_t*)"\x2d\xa7\x5d\xa5\xc8\x54\x78\xdf\x42\xdf\x0f\x91\x77\x00\x24\x1e\xd2\x82\xf5\x99";
        fct_chk(jw_sha1(input, length, &digest, &digest_len, &err) == true);
        fct_chk_eq_array(digest, digest_len, result, JW_SHA1_HASH_SIZE);
        jw_data_free(digest);

        /* SASL PLAIN */
        input = (uint8_t*)"\0username\0password";
        result = (uint8_t*)"\x5e\xf0\x59\x8\x28\x39\x11\x52\x5a\x42\xf3\xeb\xc1\x27\x82\x2b\xc1\x24\xa8\x56";
        fct_chk(jw_sha1(input, 18, &digest, &digest_len, &err) == true);
        fct_chk_eq_array(digest, digest_len, result, JW_SHA1_HASH_SIZE);
        jw_data_free(digest);

        /* empty string */
        input = (uint8_t*)"";
        result = (uint8_t*)"\xda\x39\xa3\xee\x5e\x6b\x4b\xd\x32\x55\xbf\xef\x95\x60\x18\x90\xaf\xd8\x7\x9";
        fct_chk(jw_sha1(input, 0, &digest, &digest_len, &err) == true);
        fct_chk_eq_array(digest, digest_len, result, JW_SHA1_HASH_SIZE);
        jw_data_free(digest);
    } FCT_TEST_END()

    FCT_TEST_BGN(jw_sha1_ctx_invalid_state)
    {
        jw_sha1_ctx *ctx;
        jw_err err;
        uint8_t *input, *result;
        uint8_t *digest;
        size_t length, digest_len;

        memset(&err, 0, sizeof(jw_err));

        jw_sha1_create(&ctx, &err);
        fct_chk(ctx);
        input = (uint8_t*)"a test string";
        length = strlen((const char *)input);
        fct_chk(jw_sha1_input(ctx, input, length, &err) == true);

        result = (uint8_t*)"\x2d\xa7\x5d\xa5\xc8\x54\x78\xdf\x42\xdf\x0f\x91\x77\x00\x24\x1e\xd2\x82\xf5\x99";
        fct_chk(jw_sha1_result(ctx, &digest, &digest_len, &err) == true);
        fct_chk_eq_array(digest, digest_len, result, JW_SHA1_HASH_SIZE);
        jw_data_free(digest);

        fct_chk(jw_sha1_input(ctx, input, length, &err) == false);
        fct_chk(err.code == JW_ERR_INVALID_STATE);
        fct_chk_eq_str(err.message, "invalid state");

        fct_chk(jw_sha1_result(ctx, &digest, &digest_len, &err) == false);
        fct_chk(err.code == JW_ERR_INVALID_STATE);
        fct_chk_eq_str(err.message, "invalid state");

        ctx = jw_sha1_reset(ctx);
        fct_chk(ctx);
        jw_sha1_destroy(ctx);
    } FCT_TEST_END()

    FCT_TEST_BGN(jw_hmac_sha1_createdestroy)
    {
        jw_hmac_sha1_ctx *ctx;
        jw_err      err;

        fct_chk(jw_hmac_sha1_create(NULL, 0, &ctx, &err));
        fct_chk(ctx);

        jw_hmac_sha1_destroy(ctx);
    } FCT_TEST_END()


    FCT_TEST_BGN(jw_hmac_sha1_compute_simple)
    {
        jw_hmac_sha1_ctx *ctx = NULL;
        jw_err      err;
        uint8_t     *output = NULL;
        size_t      output_len = 0;

        // https://www.cosic.esat.kuleuven.be/nessie/testvectors/
        uint8_t key[] = "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff\x01\x23\x45\x67\x89\xab\xcd\xef\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff\x01\x23\x45\x67\x89\xab\xcd\xef\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff";
        uint8_t msg[] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        uint8_t mac[] = "\xc4\xf5\x7a\xab\x0c\xdb\x8e\xf9\xb0\x4c\xb2\x6b\xe2\x52\x1d\xf3\x57\xe8\x13\x72";

        fct_chk(jw_hmac_sha1_create(key, sizeof(key)-1, &ctx, &err));
        fct_chk(ctx);

        fct_chk(jw_hmac_sha1_input(ctx, msg, sizeof(msg)-1, &err));
        fct_chk(jw_hmac_sha1_result(ctx, &output, &output_len, &err));
        fct_chk_eq_array(output, output_len, mac, JW_SHA1_HASH_SIZE);
        jw_data_free(output);
        output = NULL;

        // invalid state errors
        err.code = 0;
        err.message = NULL;
        fct_chk(!jw_hmac_sha1_input(ctx, msg, sizeof(msg)-1, &err));
        fct_chk_eq_int(err.code, JW_ERR_INVALID_STATE);
        fct_chk_eq_str(err.message, "invalid state");
        err.code = 0;
        err.message = NULL;
        fct_chk(!jw_hmac_sha1_result(ctx, &output, &output_len, &err));
        fct_chk_eq_int(err.code, JW_ERR_INVALID_STATE);
        fct_chk_eq_str(err.message, "invalid state");

        jw_hmac_sha1_destroy(ctx);
    } FCT_TEST_END()

    FCT_TEST_BGN(jw_hmac_sha1_null)
    {
        uint8_t key[] = "123";
        uint8_t mac[] = "\x8b\xc7\x21\x00\x02\xd7\x25\xec\x9d\x25\xfe\xdb\x84\x4f\xf5\x17\x4c\x94\x77\x3d";
        jw_err err;
        uint8_t *output = NULL;
        size_t output_len = 0;


        fct_req(jw_hmac_sha1(NULL,
                             0,
                             key,
                             sizeof(key)-1,
                             &output,
                             &output_len,
                             &err));

        fct_chk_eq_array(output, output_len, mac, JW_SHA1_HASH_SIZE);
        jw_data_free(output);
    } FCT_TEST_END()

    FCT_TEST_BGN(jw_hmac_sha1_short)
    {
        uint8_t key[] = "123";
        uint8_t msg[] = "456";
        uint8_t mac[] = "\x6a\xb9\x7b\xa2\x70\x78\x32\x82\xde\x3e\x9e\xe8\x4c\xb3\x52\xae\x1c\x40\x39\x6c";
        jw_err err;
        uint8_t *output = NULL;
        size_t output_len = 0;


        fct_req(jw_hmac_sha1(msg,
                             sizeof(msg)-1,
                             key,
                             sizeof(key)-1,
                             &output,
                             &output_len,
                             &err));

        fct_chk_eq_array(output, output_len, mac, JW_SHA1_HASH_SIZE);
        jw_data_free(output);
    } FCT_TEST_END()

    FCT_TEST_BGN(jw_hmac_sha1_long)
    {
        uint8_t key[128];
        uint8_t msg[] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        uint8_t mac[] = "\x7d\x0f\xcf\xef\x12\xbe\x1c\xe7\x11\xb0\xcb\x40\x00\x09\x13\xa4\x29\xc8\xa6\xf2";
        size_t i;
        jw_err err;
        uint8_t *output = NULL;
        size_t output_len = 0;

        for (i=0; i<128; i++)
        {
            key[i] = '1';
        }

        fct_req(jw_hmac_sha1(msg,
                             sizeof(msg)-1,
                             key,
                             128,
                             &output,
                             &output_len,
                             &err));

        fct_chk_eq_array(output, output_len, mac, JW_SHA1_HASH_SIZE);
        jw_data_free(output);
    } FCT_TEST_END()

} FCTMF_SUITE_END()
