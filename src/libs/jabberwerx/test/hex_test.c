/**
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

#include "fct.h"
#include "jabberwerx/util/hex.h"
#include "jabberwerx/util/mem.h"
#include <string.h>

// Warning: side-effect on V2
#undef fct_chk_eq_ustr
#define fct_chk_eq_ustr(V1, V2) \
    {                                              \
        const uint8_t *v1 = (uint8_t*)(V1);        \
        const uint8_t *v2 = (uint8_t*)(V2);        \
        const size_t v2len = sizeof((V2)) - 1;     \
        fct_xchk(memcmp(v1, v2, v2len) == 0,       \
                 "chk_eq_ustr: Expected '%s'",     \
                 V2);                              \
    }

FCTMF_SUITE_BGN(hex_test)
{
    FCT_TEST_BGN(jw_hex_encode_basic)
    {
        jw_err  err;
        char   *result;
        size_t  result_len;

        fct_chk(jw_hex_encode((const uint8_t*)"1", 1, &result, &result_len, &err) == true);
        fct_chk_eq_str(result, "31");
        fct_chk_eq_int(result_len, 2);
        jw_data_free(result);

        fct_chk(jw_hex_encode((const uint8_t*)"\x00", 1, &result, &result_len, &err) == true);
        fct_chk_eq_str(result, "00");
        fct_chk_eq_int(result_len, 2);
        jw_data_free(result);

        fct_chk(jw_hex_encode((const uint8_t*)"\x0f", 1, &result, &result_len, &err) == true);
        fct_chk_eq_str(result, "0f");
        fct_chk_eq_int(result_len, 2);
        jw_data_free(result);

        fct_chk(jw_hex_encode((const uint8_t*)"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f", 16, &result, &result_len, &err) == true);
        fct_chk_eq_str(result, "000102030405060708090a0b0c0d0e0f");
        fct_chk_eq_int(result_len, 32);
        jw_data_free(result);
    } FCT_TEST_END()

    FCT_TEST_BGN(jw_hex_decode_basic)
    {
        jw_err   err;
        uint8_t *result;
        size_t   result_len;

        fct_chk(jw_hex_decode("31", 2, &result, &result_len, &err) == true);
        fct_chk_eq_ustr(result, "1");
        fct_chk_eq_int(result_len, 1);
        jw_data_free(result);
    } FCT_TEST_END()

    FCT_TEST_BGN(jw_hex_decode_case)
    {
        jw_err   err;
        uint8_t *result;
        size_t   result_len;

        fct_chk(jw_hex_decode("31", 2, &result, &result_len, &err) == true);
        fct_chk_eq_ustr(result, "1");
        fct_chk_eq_int(result_len, 1);
        jw_data_free(result);
    } FCT_TEST_END()

    FCT_TEST_BGN(jw_hex_decode_calc_orig)
    {
        jw_err   err;
        uint8_t *result;
        size_t   result_len;

        fct_chk(jw_hex_decode("0a0b0c0d0e0f", -1, &result, &result_len, &err) == true);
        fct_chk_eq_ustr(result, "\x0a\x0b\x0c\x0d\x0e\x0f");
        fct_chk_eq_int(result_len, 6);
        jw_data_free(result);

        fct_chk(jw_hex_decode("0A0B0C0D0E0F", -1, &result, &result_len, &err) == true);
        fct_chk_eq_ustr(result, "\x0a\x0b\x0c\x0d\x0e\x0f");
        fct_chk_eq_int(result_len, 6);
        jw_data_free(result);
    } FCT_TEST_END()

    FCT_TEST_BGN(jw_hex_decode_invalid_arg)
    {
        jw_err   err;
        uint8_t *result;
        size_t   result_len;

        fct_chk((jw_hex_decode("g", 1, &result, &result_len, &err)) == false);
        fct_chk_eq_str(err.message, "invalid argument");

        fct_chk((jw_hex_decode("gg", 2, &result, &result_len, &err)) == false);
        fct_chk_eq_str(err.message, "invalid argument");

        fct_chk((jw_hex_decode("gg", -2, &result, &result_len, &err)) == false);
        fct_chk_eq_str(err.message, "invalid argument");
    }   FCT_TEST_END()
} FCTMF_SUITE_END()
