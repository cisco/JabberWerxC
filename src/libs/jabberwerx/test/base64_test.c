/**
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

#include "fct.h"
#include "jabberwerx/util/base64.h"
#include "jabberwerx/util/mem.h"
#include <string.h>

/*
    Register a multi-file test suite, linked by identitfier with call
    in test-jabberwerx.c
    note this is not a FEATURE suite (no setup/teardown)
    see fct docs for FCTMF_FEATURE_SUITE_BGN for more information.
*/
FCTMF_SUITE_BGN(base64_test)
{
    /* define test function "encode_basic" */
    FCT_TEST_BGN(jw_base64_encode_basic)
    {
        jw_err  err;
        char   *result;
        size_t  result_len;

        fct_chk(jw_base64_encode((const uint8_t*)"", 0, &result, &result_len, &err) == true);
        fct_chk_eq_int(result_len, 0);
        jw_data_free(result);

        fct_chk(jw_base64_encode((const uint8_t*)"1", 1, &result, &result_len, &err) == true);
        fct_chk(strncmp(result,  "MQ==", 4) == 0);
        fct_chk_eq_int(result_len, 4);
        jw_data_free(result);

        fct_chk(jw_base64_encode((const uint8_t*)"Aa", 2, &result, &result_len, &err) == true);
        fct_chk(strncmp(result,  "QWE=", 4) == 0);
        fct_chk_eq_int(result_len, 4);
        jw_data_free(result);

        fct_chk(jw_base64_encode((const uint8_t*)"5@B", 3, &result, &result_len, &err) == true);
        fct_chk(strncmp(result, "NUBC", 4) == 0);
        fct_chk_eq_int(result_len, 4);
        jw_data_free(result);

        fct_chk(jw_base64_encode((const uint8_t*)"G%4!", 4, &result, &result_len, &err) == true);
        fct_chk(strncmp(result, "RyU0IQ==", 8) == 0);
        fct_chk_eq_int(result_len, 8);
        jw_data_free(result);

        fct_chk(jw_base64_encode((const uint8_t*)"1234567", 7, &result, &result_len, &err) == true);
        fct_chk(strncmp(result, "MTIzNDU2Nw==", 12) == 0);
        fct_chk_eq_int(result_len, 12);
        jw_data_free(result);

        fct_chk(jw_base64_encode((const uint8_t*)"1234", 0, &result, &result_len, &err) == true);
        fct_chk(result && (*result == 0));
        fct_chk_eq_int(result_len, 0);
        jw_data_free(result);
    } FCT_TEST_END()

    FCT_TEST_BGN(jw_base64_decode_basic)
    {
        jw_err   err;
        uint8_t *result;
        size_t   result_len;

        fct_chk(jw_base64_decode("", 0, &result, &result_len, &err) == true);
        fct_chk_eq_int(result_len, 0);
        jw_data_free(result);

        fct_chk(jw_base64_decode("MQ==", 4, &result, &result_len, &err) == true);
        fct_chk(memcmp(result, "1", 1) == 0);
        fct_chk_eq_int(result_len, 1);
        jw_data_free(result);

        fct_chk(jw_base64_decode("QWE=", 4, &result, &result_len, &err) == true);
        fct_chk(memcmp(result,  "Aa", 2) == 0);
        fct_chk_eq_int(result_len, 2);
        jw_data_free(result);

        fct_chk(jw_base64_decode("NUBC", 4, &result, &result_len, &err) == true);
        fct_chk(memcmp(result, "5@B", 3) == 0);
        fct_chk_eq_int(result_len, 3);
        jw_data_free(result);

        fct_chk(jw_base64_decode("RyU0IQ==", 8, &result, &result_len, &err) == true);
        fct_chk(memcmp(result, "G%4!", 4) == 0);
        fct_chk_eq_int(result_len, 4);
        jw_data_free(result);

        fct_chk(jw_base64_decode("MTIzNDU2Nw==", 12,&result, &result_len,  &err) == true);
        fct_chk(memcmp(result, "1234567", 7) == 0);
        fct_chk_eq_int(result_len, 7);
        jw_data_free(result);

        fct_chk(jw_base64_decode("MTI=", 0, &result, &result_len,  &err) == true);
        fct_chk(result && (*result == 0));
        fct_chk_eq_int(result_len, 0);
        jw_data_free(result);
    } FCT_TEST_END()

    FCT_TEST_BGN(jw_base64_decode_calc_orig)
    {
        jw_err   err;
        uint8_t *result;
        size_t   result_len;

        fct_chk(jw_base64_decode("MQ==", -1, &result, &result_len, &err) == true);
        fct_chk(memcmp(result, "1", 1) == 0);
        fct_chk_eq_int(result_len, 1);
        jw_data_free(result);

        fct_chk(jw_base64_decode("QWE=", -1, &result, &result_len, &err) ==true);
        fct_chk(memcmp(result,  "Aa", 2) == 0);
        fct_chk_eq_int(result_len, 2);
        jw_data_free(result);

        fct_chk(jw_base64_decode("NUBC", -1, &result, &result_len, &err) == true);
        fct_chk(memcmp(result, "5@B", 3) == 0);
        fct_chk_eq_int(result_len, 3);
        jw_data_free(result);

        fct_chk(jw_base64_decode("RyU0IQ==", -1, &result, &result_len, &err) == true);
        fct_chk(memcmp(result, "G%4!", 4) == 0);
        fct_chk_eq_int(result_len, 4);
        jw_data_free(result);

        fct_chk(jw_base64_decode("MTIzNDU2Nw==", -1, &result, &result_len, &err) == true);
        fct_chk(memcmp(result, "1234567", 7) == 0);
        fct_chk_eq_int(result_len, 7);
        jw_data_free(result);

        fct_chk(jw_base64_decode("", -1, &result, &result_len,  &err) == true);
        fct_chk(result && (*result == 0));
        fct_chk_eq_int(result_len, 0);
        jw_data_free(result);
    } FCT_TEST_END()

    FCT_TEST_BGN(jw_base64_decode_invalid_arg)
    {
        jw_err   err;
        uint8_t *result;
        size_t   result_len;

        fct_chk((jw_base64_decode("YWJjDQo", 7, &result, &result_len, &err)) == false);
        fct_chk_eq_str(err.message, "invalid argument");

        fct_chk((jw_base64_decode("YWJj<A==", 8, &result, &result_len, &err)) == false);
        fct_chk_eq_str(err.message, "invalid argument");

        fct_chk((jw_base64_decode("YWJj<A==", -2, &result, &result_len, &err)) == false);
        fct_chk_eq_str(err.message, "invalid argument");
    }   FCT_TEST_END()
} FCTMF_SUITE_END()
