/**
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

/*
 *  NOTE - THIS FILE *MUST* BE SAVED WITH UTF-8 ENCODING.
 *  Failure to do so will break all utf-8 tests and data.
 */
#include <string.h>

#include <jabberwerx/jid.h>
#include <jabberwerx/util/htable.h>
#include <jabberwerx/util/mem.h>
#include "fct.h"

size_t _jid_context_cleaner_count = 0;
void _jid_context_cleaner(void *arg)
{
    UNUSED_PARAM(arg);
    ++_jid_context_cleaner_count;
}

/*typedef struct _free_results
{
    size_t num_expected_freed;
    size_t num_freed;
} free_results;

void **_expected;
size_t _num_expected;
free_results _results;

static void expected_free(void *ptr)
{
    size_t idx;

    _results.num_freed++;
    for (idx = 0; idx < _num_expected; ++idx)
    {
        if (*(_expected + idx) == ptr)
        {
            // NULL to ensure each expected is only counted once
            *(_expected + idx) = NULL;
            ++_results.num_expected_freed;
            break;
        }
    }
    free(ptr);
}
static void setup_expected_free(void **expected_ptrs, size_t num_ptrs)
{
    _expected = expected_ptrs;
    _num_expected = num_ptrs;

    _results.num_expected_freed = 0;
    _results.num_freed = 0;
    jw_data_set_memory_funcs(NULL, NULL, expected_free);
}

static free_results get_free_results()
{
    jw_data_set_memory_funcs(NULL, NULL, NULL);
    _expected = NULL;
    _num_expected = 0;
    return _results;
}
*/

FCTMF_SUITE_BGN(jid_test)
{
    /* TODO: "stress" unit tests that use 'jw_jid_create(ctx, )', 'jw_jid_copy()'
      and 'jw_jid_destroy()' awith  large (thousands) numbers of jw_jids
      (across multiple threads when practical).
    */
    FCT_TEST_BGN(jw_jid_context)
    {
        jw_jid_ctx *ctx;
        jw_err err;

        fct_req(jw_jid_context_create(5, &ctx, &err));
        jw_jid_context_destroy(ctx);

        fct_req(jw_jid_context_create(0, &ctx, &err));
        jw_jid_context_destroy(ctx);
        fct_req(jw_jid_context_create(0, &ctx, &err));
        fct_chk(jw_jid_context_get_pool(ctx) != NULL);
        _jid_context_cleaner_count = 0;
        /* if pool's cleaner works we can assume this is a good pool */
        fct_chk(jw_pool_add_cleaner(jw_jid_context_get_pool(ctx),
                                    (jw_pool_cleaner)_jid_context_cleaner,
                                    ctx,
                                    &err));
        jw_jid_context_destroy(ctx);
        fct_chk(_jid_context_cleaner_count == 1);
    } FCT_TEST_END()
    
    FCT_TEST_BGN(jw_jid_context_htable_cleaner)
    {
        jw_htable   *table;
        jw_jid_ctx  *ctx;
        jw_err      err;
        
        fct_req(jw_htable_create(0,
                                 jw_str_hashcode,
                                 jw_str_compare,
                                 &table,
                                 &err));
                                 
        fct_req(jw_jid_context_create(0, &ctx, &err));
        _jid_context_cleaner_count = 0;
        /* if pool's cleaner works we can assume this is a good pool */
        fct_req(jw_pool_add_cleaner(jw_jid_context_get_pool(ctx),
                                    (jw_pool_cleaner)_jid_context_cleaner,
                                    ctx,
                                    &err));
        
        fct_req(jw_htable_put(table,
                              "jidContext",
                              ctx,
                              jw_jid_context_htable_cleaner,
                              &err));
        // destroying a table calls the cleaner
        jw_htable_destroy(table);
        fct_chk(_jid_context_cleaner_count == 1);
    } FCT_TEST_END()

/*    FCT_TEST_BGN(jw_jid_context_destroy)
    {
        jw_jid     *jid;
        jw_jid_ctx *ctx;
        free_results results;

        void *expected[6] = {NULL};

        fct_req(jw_jid_context_create(0, &ctx, NULL));

        fct_req(jw_jid_create(ctx, "foo@bar", &jid, NULL));
        expected[0] = (void *)jw_jid_get_localpart(jid);
        expected[1] = jid;
        fct_req(jw_jid_create(ctx, "foo@bar/baz", &jid, NULL));
        expected[2] = jid;
        fct_req(jw_jid_create(ctx, "foo@bar/baz1", &jid, NULL));
        expected[3] = jid;
        fct_req(jw_jid_create(ctx, "foo@bar/baz2", &jid, NULL));
        expected[4] = jid;

        setup_expected_free(expected, 5);
        jw_jid_context_destroy(ctx);
        results = get_free_results();

        fct_chk_eq_int(results.num_expected_freed, 5);
        fct_chk_eq_int(results.num_freed, 14);
    } FCT_TEST_END()
*/
    FCT_TEST_BGN(jw_jid_valid)
    {
        fct_chk(jw_jid_valid("foo@bar/baz"));
        fct_chk(jw_jid_valid("boo/foo@bar@baz"));
        fct_chk(jw_jid_valid("foo@-internal"));
        // negative test
        fct_chk(!jw_jid_valid("foo@bar@baz"));
        fct_chk(!jw_jid_valid("@foo@bar/baz"));
        fct_chk(!jw_jid_valid("bar/"));
        fct_chk(!jw_jid_valid("foo@bar/"));
        fct_chk(!jw_jid_valid("foo@"));
        fct_chk(!jw_jid_valid("foo@@bar"));
        fct_chk(!jw_jid_valid("foo@bar."));
        fct_chk(!jw_jid_valid("foo@bar..baz"));
        fct_chk(jw_jid_valid("foo@012345678901234567890123456789012345678901234567890123456789012"));
        fct_chk(!jw_jid_valid("foo@0123456789012345678901234567890123456789012345678901234567890123"));
        fct_chk(!jw_jid_valid("foo@-internal-"));
        fct_chk(!jw_jid_valid("foo@-bar"));
        fct_chk(!jw_jid_valid("foo@bar-"));
    } FCT_TEST_END()

    FCT_TEST_BGN(jw_jid_create)
    {
        jw_jid     *jid, *bjid;
        jw_err     err;
        jw_jid_ctx *ctx;

        fct_req(jw_jid_context_create(0, &ctx, &err));

        /* happy path full*/

        fct_chk(jw_jid_create(ctx, "foo@bar/baz", &jid, &err));

        fct_chk(jid != NULL);
        fct_chk(jw_jid_get_context(jid) == ctx);
        fct_chk_eq_str(jw_jid_get_localpart(jid), "foo");
        fct_chk_eq_str(jw_jid_get_domain(jid), "bar");
        fct_chk_eq_str(jw_jid_get_resource(jid), "baz");
        fct_chk_eq_str(jw_jid_get_bare(jid), "foo@bar");
        fct_chk_eq_str(jw_jid_get_full(jid), "foo@bar/baz");
        bjid = jw_jid_get_bare_jid(jid);
        fct_chk(jid != bjid);
        fct_chk_eq_str(jw_jid_get_localpart(bjid), "foo");
        fct_chk_eq_str(jw_jid_get_domain(bjid), "bar");
        fct_chk(jw_jid_get_resource(bjid) == NULL);
        fct_chk_eq_str(jw_jid_get_bare(bjid), "foo@bar");
        fct_chk_eq_str(jw_jid_get_full(bjid), "foo@bar");
        jw_jid_destroy(jid);
        jw_jid_destroy(bjid);

        /* happy path bare */
        fct_chk(jw_jid_create(ctx, "foo@bar", &jid, &err));
        fct_chk(jid != NULL);
        fct_chk_eq_str(jw_jid_get_localpart(jid), "foo");
        fct_chk_eq_str(jw_jid_get_domain(jid), "bar");
        fct_chk(jw_jid_get_resource(jid) == NULL);
        fct_chk_eq_str(jw_jid_get_bare(jid), "foo@bar");
        fct_chk_eq_str(jw_jid_get_full(jid), "foo@bar");
        bjid = jw_jid_get_bare_jid(jid);
        fct_chk(bjid == jid);
        jw_jid_destroy(jid);
        jw_jid_destroy(bjid);

        /* happy path domain/resource */
        fct_chk(jw_jid_create(ctx, "bar/baz", &jid, &err));
        fct_chk(jw_jid_get_localpart(jid) == NULL);
        fct_chk_eq_str(jw_jid_get_domain(jid), "bar");
        fct_chk_eq_str(jw_jid_get_resource(jid), "baz");
        fct_chk_eq_str(jw_jid_get_bare(jid), "bar");
        fct_chk_eq_str(jw_jid_get_full(jid), "bar/baz");
        bjid = jw_jid_get_bare_jid(jid);
        fct_chk(bjid != jid);
        fct_chk(jw_jid_get_localpart(bjid) == NULL);
        fct_chk_eq_str(jw_jid_get_domain(bjid), "bar");
        fct_chk(jw_jid_get_resource(bjid) == NULL);
        fct_chk_eq_str(jw_jid_get_bare(bjid), "bar");
        fct_chk_eq_str(jw_jid_get_full(bjid), "bar");
        jw_jid_destroy(jid);
        jw_jid_destroy(bjid);

        /* happy path domain only */
        fct_chk(jw_jid_create(ctx, "bar", &jid, &err));
        fct_chk(jw_jid_get_localpart(jid) == NULL);
        fct_chk_eq_str(jw_jid_get_domain(jid), "bar");
        fct_chk(jw_jid_get_resource(jid) == NULL);
        fct_chk_eq_str(jw_jid_get_bare(jid), "bar");
        fct_chk_eq_str(jw_jid_get_full(jid), "bar");
        bjid = jw_jid_get_bare_jid(jid);
        fct_chk(bjid == jid);
        jw_jid_destroy(jid);
        jw_jid_destroy(bjid);

        // test quick fail path
        fct_req(!jw_jid_create(ctx, NULL, &jid, &err));
        fct_chk_eq_int(JW_ERR_INVALID_ARG, err.code);
        
        /* test Parse @ in Resource 2 */
        fct_chk(jw_jid_create(ctx, "foo@bar/baz@bleh", &jid, &err));
        fct_chk_eq_str(jw_jid_get_localpart(jid), "foo");
        fct_chk_eq_str(jw_jid_get_domain(jid), "bar");
        fct_chk_eq_str(jw_jid_get_resource(jid), "baz@bleh");
        fct_chk_eq_str(jw_jid_get_bare(jid), "foo@bar");
        fct_chk_eq_str(jw_jid_get_full(jid), "foo@bar/baz@bleh");
        bjid = jw_jid_get_bare_jid(jid);
        fct_chk(jid != bjid);
        fct_chk_eq_str(jw_jid_get_bare(bjid), "foo@bar");
        fct_chk_eq_str(jw_jid_get_full(bjid), "foo@bar");
        jw_jid_destroy(jid);
        jw_jid_destroy(bjid);

        /* test Parse / in Resource */
        fct_chk(jw_jid_create(ctx, "foo@bar/baz/bleh", &jid, &err));
        fct_chk_eq_str(jw_jid_get_localpart(jid), "foo");
        fct_chk_eq_str(jw_jid_get_domain(jid), "bar");
        fct_chk_eq_str(jw_jid_get_resource(jid), "baz/bleh");
        fct_chk_eq_str(jw_jid_get_bare(jid), "foo@bar");
        fct_chk_eq_str(jw_jid_get_full(jid), "foo@bar/baz/bleh");
        bjid = jw_jid_get_bare_jid(jid);
        fct_chk(jid != bjid);
        fct_chk_eq_str(jw_jid_get_bare(bjid), "foo@bar");
        fct_chk_eq_str(jw_jid_get_full(bjid), "foo@bar");
        jw_jid_destroy(jid);
        jw_jid_destroy(bjid);

        /* test Parse two @'s in Resource */
        fct_chk(jw_jid_create(ctx, "bar/foo@baz@bleh", &jid, &err));
        fct_chk(jw_jid_get_localpart(jid) == NULL);
        fct_chk_eq_str(jw_jid_get_domain(jid), "bar");
        fct_chk_eq_str(jw_jid_get_resource(jid), "foo@baz@bleh");
        fct_chk_eq_str(jw_jid_get_bare(jid), "bar");
        fct_chk_eq_str(jw_jid_get_full(jid), "bar/foo@baz@bleh");
        bjid = jw_jid_get_bare_jid(jid);
        fct_chk(jid != bjid);
        fct_chk_eq_str(jw_jid_get_bare(bjid), "bar");
        fct_chk_eq_str(jw_jid_get_full(bjid), "bar");
        jw_jid_destroy(jid);
        jw_jid_destroy(bjid);
        /* fail tests */
        jid = NULL;
        fct_chk(!jw_jid_create(ctx, "foo@bar@baz", &jid, &err));
        fct_chk(err.code == JW_ERR_INVALID_ARG);
        fct_chk(jid == NULL);
        jid = NULL;
        fct_chk(!jw_jid_create(ctx, "@foo@bar/baz", &jid, &err));
        fct_chk(err.code == JW_ERR_INVALID_ARG);
        fct_chk(jid == NULL);
        fct_chk(!jw_jid_create(ctx, "bar/", &jid, &err));
        fct_chk(err.code == JW_ERR_INVALID_ARG);
        fct_chk(jid == NULL);
        fct_chk(!jw_jid_create(ctx, "foo@bar/", &jid, &err));
        fct_chk(err.code == JW_ERR_INVALID_ARG);
        fct_chk(jid == NULL);
        fct_chk(!jw_jid_create(ctx, "foo@", &jid, &err));
        fct_chk(err.code == JW_ERR_INVALID_ARG);
        fct_chk(jid == NULL);
        fct_chk(!jw_jid_create(ctx, "foo@@bar", &jid, &err));
        fct_chk(err.code == JW_ERR_INVALID_ARG);
        fct_chk(jid == NULL);
        fct_chk(!jw_jid_create(ctx, "\\20foo@bar", &jid, &err));
        fct_chk(err.code == JW_ERR_INVALID_ARG);
        fct_chk(jid == NULL);
        fct_chk(!jw_jid_create(ctx, "foo\\20@bar", &jid, &err));
        fct_chk(err.code == JW_ERR_INVALID_ARG);
        fct_chk(jid == NULL);
        fct_chk(!jw_jid_create(ctx, "", &jid, &err));
        fct_chk(err.code == JW_ERR_INVALID_ARG);
        fct_chk(jid == NULL);

        /* test resource prep, make sure capitalization remains the same */
        fct_chk(jw_jid_create(ctx, "foo@bar/Baz", &jid, &err));
        fct_chk(strcmp(jw_jid_get_resource(jid), "Baz") == 0);
        jw_jid_destroy(jid);
        /* leave several jids in ctx at destruction time.
          test fails if program crashes. additional tests can be added once
          memory tracking is implemented */
        jw_jid_create(ctx, "foo@bar/baz", &jid, NULL);
        jw_jid_create(ctx, "another-different-localpart@bar/baz", &bjid, NULL);
        jw_jid_context_destroy(ctx);
        /* todo "too large" jid (> 1023@1023/1023) */
    } FCT_TEST_END()

    FCT_TEST_BGN(jw_jid_create_by_parts)
    {
        jw_jid *jid, *bjid;
        jw_err err;
        jw_jid_ctx *ctx;

        fct_req(jw_jid_context_create(0, &ctx, &err));
        fct_chk(jw_jid_create_by_parts(ctx, "foo", "bar", "baz", &jid, &err));
        fct_chk(jid != NULL);
        fct_chk_eq_str(jw_jid_get_localpart(jid), "foo");
        fct_chk_eq_str(jw_jid_get_domain(jid), "bar");
        fct_chk_eq_str(jw_jid_get_resource(jid), "baz");
        fct_chk_eq_str(jw_jid_get_bare(jid), "foo@bar");
        fct_chk_eq_str(jw_jid_get_full(jid), "foo@bar/baz");
        bjid = jw_jid_get_bare_jid(jid);
        fct_chk(jid != bjid);
        fct_chk_eq_str(jw_jid_get_localpart(bjid), "foo");
        fct_chk_eq_str(jw_jid_get_domain(bjid), "bar");
        fct_chk(jw_jid_get_resource(bjid) == NULL);
        fct_chk_eq_str(jw_jid_get_bare(bjid), "foo@bar");
        fct_chk_eq_str(jw_jid_get_full(bjid), "foo@bar");
        jw_jid_destroy(jid);
        jw_jid_destroy(bjid);
        /* other happy path tests replicated as parts */
        fct_chk(jw_jid_create_by_parts(ctx, "foo", "bar", NULL, &jid, &err));
        fct_chk(jid != NULL);
        fct_chk_eq_str(jw_jid_get_localpart(jid), "foo");
        fct_chk_eq_str(jw_jid_get_domain(jid), "bar");
        fct_chk_eq_str(jw_jid_get_resource(jid), NULL);
        fct_chk_eq_str(jw_jid_get_bare(jid), "foo@bar");
        fct_chk_eq_str(jw_jid_get_full(jid), "foo@bar");
        bjid = jw_jid_get_bare_jid(jid);
        fct_chk(bjid == jid);  /* bjid, jid reference the same memory */
        jw_jid_destroy(jid);
        jw_jid_destroy(bjid);

        fct_chk(jw_jid_create_by_parts(ctx, "foo", "bar", "baz@bleh", &jid, &err));
        fct_chk(jid != NULL);
        fct_chk_eq_str(jw_jid_get_localpart(jid), "foo");
        fct_chk_eq_str(jw_jid_get_domain(jid), "bar");
        fct_chk_eq_str(jw_jid_get_resource(jid), "baz@bleh");
        fct_chk_eq_str(jw_jid_get_bare(jid), "foo@bar");
        fct_chk_eq_str(jw_jid_get_full(jid), "foo@bar/baz@bleh");
        bjid = jw_jid_get_bare_jid(jid);
        fct_chk(jid != bjid);
        fct_chk_eq_str(jw_jid_get_localpart(bjid), "foo");
        fct_chk_eq_str(jw_jid_get_domain(bjid), "bar");
        fct_chk(jw_jid_get_resource(bjid) == NULL);
        fct_chk_eq_str(jw_jid_get_bare(bjid), "foo@bar");
        fct_chk_eq_str(jw_jid_get_full(bjid), "foo@bar");
        jw_jid_destroy(jid);
        jw_jid_destroy(bjid);

        fct_chk(jw_jid_create_by_parts(ctx, "foo", "bar", "baz/bleh", &jid, &err));
        fct_chk(jid != NULL);
        fct_chk_eq_str(jw_jid_get_localpart(jid), "foo");
        fct_chk_eq_str(jw_jid_get_domain(jid), "bar");
        fct_chk_eq_str(jw_jid_get_resource(jid), "baz/bleh");
        fct_chk_eq_str(jw_jid_get_bare(jid), "foo@bar");
        fct_chk_eq_str(jw_jid_get_full(jid), "foo@bar/baz/bleh");
        bjid = jw_jid_get_bare_jid(jid);
        fct_chk(jid != bjid);
        fct_chk_eq_str(jw_jid_get_localpart(bjid), "foo");
        fct_chk_eq_str(jw_jid_get_domain(bjid), "bar");
        fct_chk(jw_jid_get_resource(bjid) == NULL);
        fct_chk_eq_str(jw_jid_get_bare(bjid), "foo@bar");
        fct_chk_eq_str(jw_jid_get_full(bjid), "foo@bar");
        jw_jid_destroy(jid);
        jw_jid_destroy(bjid);

        jid = NULL;
        fct_chk(!jw_jid_create_by_parts(ctx, "", "boo@foo@bar", "", &jid, &err));
        fct_chk(err.code == JW_ERR_INVALID_ARG);
        fct_chk(jid == NULL);
        /*  other fail tests replicated as parts */
        jid = NULL;
        fct_chk(!jw_jid_create_by_parts(ctx, "", "bar/", "", &jid, &err));
        fct_chk(err.code == JW_ERR_INVALID_ARG);
        fct_chk(jid == NULL);
        jid = NULL;
        fct_chk(!jw_jid_create_by_parts(ctx, "", "foo@", "", &jid, &err));
        fct_chk(err.code == JW_ERR_INVALID_ARG);
        fct_chk(jid == NULL);
        jid = NULL;
        fct_chk(!jw_jid_create_by_parts(ctx, "", "foo@@bar", "", &jid, &err));
        fct_chk(err.code == JW_ERR_INVALID_ARG);
        fct_chk(jid == NULL);

        // more invalid domain strings
        fct_chk(!jw_jid_create_by_parts(ctx, NULL, "foo\x7e", NULL, &jid, &err));
        fct_chk(err.code == JW_ERR_INVALID_ARG);
        fct_chk(!jw_jid_create_by_parts(ctx, NULL, "xn--foo\x7e", NULL, &jid, &err));
        fct_chk(err.code == JW_ERR_INVALID_ARG);
        fct_chk(!jw_jid_create_by_parts(ctx, NULL, "xn--foo志翔", NULL, &jid, &err));
        fct_chk(err.code == JW_ERR_INVALID_ARG);
        fct_chk(!jw_jid_create_by_parts(ctx, NULL, "志翔志翔志翔志翔志翔志翔志翔志翔志翔志翔志翔", NULL, &jid, &err));
        fct_chk(err.code == JW_ERR_INVALID_ARG);
        fct_chk(!jw_jid_create_by_parts(ctx, NULL, "志翔志翔志翔志翔志翔志翔志翔志翔志翔志翔志.志翔志翔志翔志翔志翔志翔志翔志翔志翔志翔志.志翔志翔志翔志翔志翔志翔志翔志翔志翔志翔志.志翔志翔志翔志翔志翔志翔志翔志翔志翔志翔志.志翔志翔志翔志翔志翔志翔志翔志翔志翔志翔志.志翔志翔志翔志翔志翔志翔志翔志翔志翔志翔志.志翔志翔志翔志翔志翔志翔志翔志翔志翔志翔志.志翔志翔志翔志翔志翔志翔志翔志翔志翔志翔志", NULL, &jid, &err));
        fct_chk(err.code == JW_ERR_INVALID_ARG);

        // test ipv6
        fct_chk(jw_jid_create_by_parts(ctx, NULL, "[::1]", NULL, &jid, &err));
        jw_jid_destroy(jid);
        fct_chk(jw_jid_create_by_parts(ctx, NULL, "[::ae]", NULL, &jid, &err));
        jw_jid_destroy(jid);
        fct_chk(jw_jid_create_by_parts(ctx, NULL, "[EA:aE::ae]", NULL, &jid, &err));
        jw_jid_destroy(jid);
        fct_chk(!jw_jid_create_by_parts(ctx, NULL, "[]", NULL, &jid, &err));
        fct_chk(err.code == JW_ERR_INVALID_ARG);
        fct_chk(!jw_jid_create_by_parts(ctx, NULL, "[", NULL, &jid, &err));
        fct_chk(err.code == JW_ERR_INVALID_ARG);
        fct_chk(!jw_jid_create_by_parts(ctx, NULL, "]", NULL, &jid, &err));
        fct_chk(err.code == JW_ERR_INVALID_ARG);
        fct_chk(!jw_jid_create_by_parts(ctx, NULL, "[:wq]", NULL, &jid, &err));
        fct_chk(err.code == JW_ERR_INVALID_ARG);

        // test input length limits
        char buf4k1[4098];
        memset(buf4k1, 'a', 4097);
        buf4k1[4097] = '\0';
        fct_chk(!jw_jid_create_by_parts(ctx, buf4k1, "domain", NULL, &jid, &err));
        fct_chk(err.code == JW_ERR_INVALID_ARG);
        fct_chk(!jw_jid_create_by_parts(ctx, NULL, buf4k1, NULL, &jid, &err));
        fct_chk(err.code == JW_ERR_INVALID_ARG);
        fct_chk(!jw_jid_create_by_parts(ctx, NULL, "domain", buf4k1, &jid, &err));
        fct_chk(err.code == JW_ERR_INVALID_ARG);

        jw_jid_context_destroy(ctx);
    } FCT_TEST_END()

    FCT_TEST_BGN(jw_jid_copy)
    {
        jw_jid     *ojid, *cjid;
        jw_err     err;
        jw_jid_ctx *ctx;

        fct_req(jw_jid_context_create(0, &ctx, &err));
        fct_chk(jw_jid_create(ctx, "foo@bar/baz", &ojid, NULL));
        cjid = jw_jid_copy(ojid);
        fct_chk(cjid == ojid);
        jw_jid_destroy(cjid);
        cjid = jw_jid_copy(jw_jid_get_bare_jid(ojid));
        jw_jid_destroy(ojid);
        fct_chk(jw_jid_create(ctx, "foo@bar/baz", &ojid, NULL));
        fct_chk(cjid == jw_jid_get_bare_jid(cjid));
        jw_jid_destroy(cjid);
        jw_jid_destroy(ojid);
        jw_jid_context_destroy(ctx);
    } FCT_TEST_END()

    FCT_TEST_BGN(jw_jid_import)
    {
        fct_chk(true);
    } FCT_TEST_END()

    FCT_TEST_BGN(jw_jid_refcounts)
    {
        jw_jid     *full1, *full2, *bare1, *bare2;
        /* jw_jid     *t1; */
        jw_err     err;
        jw_jid_ctx *ctx;

        fct_req(jw_jid_context_create(0, &ctx, &err));
        fct_chk(jw_jid_create(ctx, "foo@bar/baz1", &full1, NULL)); /* bj 1 */
        fct_chk(jw_jid_create(ctx, "foo@bar/baz2", &full2, NULL)); /* bj 2 */
        bare1 = jw_jid_get_bare_jid(full1);
        fct_chk(bare1 == jw_jid_get_bare_jid(full2));
        fct_chk(jw_jid_create(ctx, "foo@bar", &bare2, NULL)); /* bj 3 */
        fct_chk(bare1 == bare2);
        jw_jid_destroy(bare2); /* bj 2 */
        jw_jid_destroy(full1); /* bj 1 */
        fct_chk(jw_jid_create(ctx, "foo@bar", &bare2, NULL)); /* bj 2 */
        fct_chk(bare1 == bare2);
        jw_jid_destroy(full2); /* bj 1 */
        jw_jid_destroy(bare2); /* bj 0 -- bare jid should be free */
        fct_chk(jw_jid_create(ctx, "foo@bar1/baz1", &full1, NULL)); /* fj 1 */
        fct_chk(jw_jid_create(ctx, "foo@bar1/baz1", &full2, NULL)); /* fj 2 */
        fct_chk(full1 == full2);
        jw_jid_destroy(full2); /*fj 1 */
        fct_chk(jw_jid_create(ctx, "foo@bar1/baz1", &full2, NULL)); /*fj 2 */
        fct_chk(full1 == full2);
        /* t1 = full1; */
        jw_jid_destroy(full1); /* fj 1 */
        jw_jid_destroy(full2); /* fj 0 */
        fct_chk(jw_jid_create(ctx, "foo@bar/baz", &bare2, NULL)); /* bj 1 */
        /* todo this compare is counting on bare2 not allocated in exact
           same place, doesn't pass reliably. removing until a full-proof
           method is found (mem check)
        fct_chk(bare1 != jw_jid_get_bare_jid(bare2));
        */
        jw_jid_destroy(bare2); /* bj 0 */
        fct_chk(jw_jid_create(ctx, "foo@bar1/baz1", &full1, NULL)); /* fj 1 */
        /* todo this compare is counting on full1 not allocated in exact
           same place, doesn't pass reliably. removing until a full-proof
           method is found (mem check)
        fct_chk(t1 != full1);
        */
        jw_jid_destroy(full1); /* fj 0 */
        jw_jid_destroy(bare1);
        jw_jid_context_destroy(ctx);
    } FCT_TEST_END()

    FCT_TEST_BGN(jw_jid_escape_localpart)
    {
        char *buff;
        size_t buff_len;
        jw_err err;

        fct_chk(jw_jid_escape_localpart("foo", &buff, &buff_len, &err));
        fct_chk_eq_str("foo", buff);
        fct_chk(buff_len == 3);
        jw_data_free(buff);
        fct_chk(jw_jid_escape_localpart("fo  o", &buff, &buff_len, &err));
        fct_chk_eq_str("fo\\20\\20o", buff);
        fct_chk(buff_len == 9);
        jw_data_free(buff);
        fct_chk(jw_jid_escape_localpart("fo\\o", &buff, &buff_len, &err));
        fct_chk_eq_str("fo\\o", buff);
        fct_chk(buff_len == 4);
        jw_data_free(buff);
        fct_chk(jw_jid_escape_localpart("fo\\5co", &buff, &buff_len, &err));
        fct_chk_eq_str("fo\\5c5co", buff);
        fct_chk(buff_len == 8);
        jw_data_free(buff);
        fct_chk(jw_jid_escape_localpart("fo/o", &buff, &buff_len, &err));
        fct_chk_eq_str("fo\\2fo", buff);
        fct_chk(buff_len == 6);
        jw_data_free(buff);
        fct_chk(jw_jid_escape_localpart("fo&o", &buff, &buff_len, &err));
        fct_chk_eq_str("fo\\26o", buff);
        fct_chk(buff_len == 6);
        jw_data_free(buff);
        fct_chk(jw_jid_escape_localpart("fo<o", &buff, &buff_len, &err));
        fct_chk_eq_str("fo\\3co", buff);
        fct_chk(buff_len == 6);
        jw_data_free(buff);
        fct_chk(jw_jid_escape_localpart("fo>o", &buff, &buff_len, &err));
        fct_chk_eq_str("fo\\3eo", buff);
        fct_chk(buff_len == 6);
        jw_data_free(buff);
        fct_chk(jw_jid_escape_localpart("fo'o", &buff, &buff_len, &err));
        fct_chk_eq_str("fo\\27o", buff);
        fct_chk(buff_len == 6);
        jw_data_free(buff);
        fct_chk(jw_jid_escape_localpart("fo\\\"o", &buff, &buff_len, &err));
        fct_chk_eq_str("fo\\\\22o", buff);
        fct_chk(buff_len == 7);
        jw_data_free(buff);
        fct_chk(jw_jid_escape_localpart("fo@o", &buff, &buff_len, &err));
        fct_chk_eq_str("fo\\40o", buff);
        fct_chk(buff_len == 6);
        jw_data_free(buff);
        fct_chk(jw_jid_escape_localpart("fo@:o", &buff, &buff_len, &err));
        fct_chk_eq_str("fo\\40\\3ao", buff);
        fct_chk(buff_len == 9);
        jw_data_free(buff);
        fct_chk(jw_jid_escape_localpart("fo\\\\@o", &buff, &buff_len, &err));
        fct_chk_eq_str("fo\\\\\\40o", buff);
        fct_chk(buff_len == 8);
        jw_data_free(buff);
        fct_chk(jw_jid_escape_localpart("foo", &buff, NULL, &err));
        fct_chk_eq_str("foo", buff);
        jw_data_free(buff);

        fct_chk(jw_jid_escape_localpart("\\20", &buff, &buff_len, &err));
        fct_chk_eq_str("\\5c20", buff);
        fct_chk(buff_len == 5);
        jw_data_free(buff);
        fct_chk(jw_jid_escape_localpart("\\22", &buff, &buff_len, &err));
        fct_chk_eq_str("\\5c22", buff);
        fct_chk(buff_len == 5);
        jw_data_free(buff);
        fct_chk(jw_jid_escape_localpart("\\26", &buff, &buff_len, &err));
        fct_chk_eq_str("\\5c26", buff);
        fct_chk(buff_len == 5);
        jw_data_free(buff);
        fct_chk(jw_jid_escape_localpart("\\27", &buff, &buff_len, &err));
        fct_chk_eq_str("\\5c27", buff);
        fct_chk(buff_len == 5);
        jw_data_free(buff);
        fct_chk(jw_jid_escape_localpart("\\2f", &buff, &buff_len, &err));
        fct_chk_eq_str("\\5c2f", buff);
        fct_chk(buff_len == 5);
        jw_data_free(buff);
        fct_chk(jw_jid_escape_localpart("\\3a", &buff, &buff_len, &err));
        fct_chk_eq_str("\\5c3a", buff);
        fct_chk(buff_len == 5);
        jw_data_free(buff);
        fct_chk(jw_jid_escape_localpart("\\3c", &buff, &buff_len, &err));
        fct_chk_eq_str("\\5c3c", buff);
        fct_chk(buff_len == 5);
        jw_data_free(buff);
        fct_chk(jw_jid_escape_localpart("\\3e", &buff, &buff_len, &err));
        fct_chk_eq_str("\\5c3e", buff);
        fct_chk(buff_len == 5);
        jw_data_free(buff);
        fct_chk(jw_jid_escape_localpart("\\40", &buff, &buff_len, &err));
        fct_chk_eq_str("\\5c40", buff);
        fct_chk(buff_len == 5);
        jw_data_free(buff);
        fct_chk(jw_jid_escape_localpart("\\5c", &buff, &buff_len, &err));
        fct_chk_eq_str("\\5c5c", buff);
        fct_chk(buff_len == 5);
        jw_data_free(buff);

        fct_chk(jw_jid_escape_localpart("foo\\'", &buff, &buff_len, &err));
        fct_chk_eq_str("foo\\\\27", buff);
        fct_chk(buff_len == 7);
        jw_data_free(buff);
        fct_chk(jw_jid_escape_localpart("foo\\5c@", &buff, &buff_len, &err));
        fct_chk_eq_str("foo\\5c5c\\40", buff);
        fct_chk(buff_len == 11);
        jw_data_free(buff);
        fct_chk(jw_jid_escape_localpart("foo\\\\&", &buff, &buff_len, &err));
        fct_chk_eq_str("foo\\\\\\26", buff);
        fct_chk(buff_len == 8);
        jw_data_free(buff);
        fct_chk(jw_jid_escape_localpart("foo@@\"\\", &buff, &buff_len, &err));
        fct_chk_eq_str("foo\\40\\40\\22\\", buff);
        fct_chk(buff_len == 13);
        jw_data_free(buff);
        fct_chk(jw_jid_escape_localpart("foo\\", &buff, &buff_len, &err));
        fct_chk_eq_str("foo\\", buff);
        fct_chk(buff_len == 4);
        jw_data_free(buff);
        fct_chk(jw_jid_escape_localpart("&foo&\\\\40\\", &buff, &buff_len, &err));
        fct_chk_eq_str("\\26foo\\26\\\\5c40\\", buff);
        fct_chk(buff_len == 16);
        jw_data_free(buff);
        fct_chk(jw_jid_escape_localpart("<script>alert(\"'hi'\") </script>&:@\\", &buff, &buff_len, &err));
        fct_chk_eq_str("\\3cscript\\3ealert(\\22\\27hi\\27\\22)\\20\\3c\\2fscript\\3e\\26\\3a\\40\\", buff);
        fct_chk(buff_len == 61);
        jw_data_free(buff);


        fct_chk(jw_jid_escape_localpart(NULL, &buff, &buff_len, &err));
        fct_chk(!buff);
        fct_chk(!buff_len);

        fct_chk(jw_jid_escape_localpart("", &buff, &buff_len, &err));
        fct_chk_eq_str(buff, "");
        fct_chk(buff_len == 0);
        jw_data_free(buff);

        fct_chk(jw_jid_escape_localpart("する特", &buff, &buff_len, &err));
        fct_chk_eq_str("する特", buff);
        fct_chk(buff_len == 9);
        jw_data_free(buff);
        fct_chk(jw_jid_escape_localpart("する  特", &buff, &buff_len, &err));
        fct_chk_eq_str("する\\20\\20特", buff);
        fct_chk(buff_len == 15);
        jw_data_free(buff);
        fct_chk(jw_jid_escape_localpart("する\\特", &buff, &buff_len, &err));
        fct_chk_eq_str("する\\特", buff);
        fct_chk(buff_len == 10);
        jw_data_free(buff);
        fct_chk(jw_jid_escape_localpart("する\\5c特", &buff, &buff_len, &err));
        fct_chk_eq_str("する\\5c5c特", buff);
        fct_chk(buff_len == 14);
        jw_data_free(buff);
        fct_chk(jw_jid_escape_localpart("する/特", &buff, &buff_len, &err));
        fct_chk_eq_str("する\\2f特", buff);
        fct_chk(buff_len == 12);
        jw_data_free(buff);
        fct_chk(jw_jid_escape_localpart("する&特", &buff, &buff_len, &err));
        fct_chk_eq_str("する\\26特", buff);
        fct_chk(buff_len == 12);
        jw_data_free(buff);
        fct_chk(jw_jid_escape_localpart("する<特", &buff, &buff_len, &err));
        fct_chk_eq_str("する\\3c特", buff);
        fct_chk(buff_len == 12);
        jw_data_free(buff);
        fct_chk(jw_jid_escape_localpart("する>特", &buff, &buff_len, &err));
        fct_chk_eq_str("する\\3e特", buff);
        fct_chk(buff_len == 12);
        jw_data_free(buff);
        fct_chk(jw_jid_escape_localpart("する'特", &buff, &buff_len, &err));
        fct_chk_eq_str("する\\27特", buff);
        fct_chk(buff_len == 12);
        jw_data_free(buff);
        fct_chk(jw_jid_escape_localpart("する\\\"特", &buff, &buff_len, &err));
        fct_chk_eq_str("する\\\\22特", buff);
        fct_chk(buff_len == 13);
        jw_data_free(buff);
        fct_chk(jw_jid_escape_localpart("する@特", &buff, &buff_len, &err));
        fct_chk_eq_str("する\\40特", buff);
        fct_chk(buff_len == 12);
        jw_data_free(buff);
    } FCT_TEST_END()

    FCT_TEST_BGN(jw_jid_unescape_localpart)
    {
        char *buff;
        size_t buff_len;
        jw_err err;

        fct_chk(jw_jid_unescape_localpart("foo", &buff, &buff_len, &err));
        fct_chk_eq_str("foo", buff);
        fct_chk(buff_len == 3);
        jw_data_free(buff);
        fct_chk(jw_jid_unescape_localpart("fo\\20\\20o", &buff, &buff_len, &err));
        fct_chk_eq_str("fo  o", buff);
        fct_chk(buff_len == 5);
        jw_data_free(buff);
        fct_chk(jw_jid_unescape_localpart("\\", &buff, &buff_len, &err));
        fct_chk_eq_str("\\", buff);
        fct_chk(buff_len == 1);
        jw_data_free(buff);
        fct_chk(jw_jid_unescape_localpart("\\5", &buff, &buff_len, &err));
        fct_chk_eq_str("\\5", buff);
        fct_chk(buff_len == 2);
        jw_data_free(buff);
        fct_chk(jw_jid_unescape_localpart("\\5c", &buff, &buff_len, &err));
        fct_chk_eq_str("\\", buff);
        fct_chk(buff_len == 1);
        jw_data_free(buff);
        fct_chk(jw_jid_unescape_localpart("fo\\5co", &buff, &buff_len, &err));
        fct_chk_eq_str("fo\\o", buff);
        fct_chk(buff_len == 4);
        jw_data_free(buff);
        fct_chk(jw_jid_unescape_localpart("fo\\5c5co", &buff, &buff_len, &err));
        fct_chk_eq_str("fo\\5co", buff);
        fct_chk(buff_len == 6);
        jw_data_free(buff);
        fct_chk(jw_jid_unescape_localpart("fo\\2fo", &buff, &buff_len, &err));
        fct_chk_eq_str("fo/o", buff);
        fct_chk(buff_len == 4);
        jw_data_free(buff);
        fct_chk(jw_jid_unescape_localpart("fo\\26o", &buff, &buff_len, &err));
        fct_chk_eq_str("fo&o", buff);
        fct_chk(buff_len == 4);
        jw_data_free(buff);
        fct_chk(jw_jid_unescape_localpart("fo\\3co", &buff, &buff_len, &err));
        fct_chk_eq_str("fo<o", buff);
        fct_chk(buff_len == 4);
        jw_data_free(buff);
        fct_chk(jw_jid_unescape_localpart("fo\\3eo", &buff, &buff_len, &err));
        fct_chk_eq_str("fo>o", buff);
        fct_chk(buff_len == 4);
        jw_data_free(buff);
        fct_chk(jw_jid_unescape_localpart("fo\\27o", &buff, &buff_len, &err));
        fct_chk_eq_str("fo'o", buff);
        fct_chk(buff_len == 4);
        jw_data_free(buff);
        fct_chk(jw_jid_unescape_localpart("fo\\5c\\22o", &buff, &buff_len, &err));
        fct_chk_eq_str("fo\\\"o", buff);
        fct_chk(buff_len == 5);
        jw_data_free(buff);
        fct_chk(jw_jid_unescape_localpart("fo\\40o", &buff, &buff_len, &err));
        fct_chk_eq_str("fo@o", buff);
        fct_chk(buff_len == 4);
        jw_data_free(buff);
        fct_chk(jw_jid_unescape_localpart("fo\\40\\3ao", &buff, &buff_len, &err));
        fct_chk_eq_str("fo@:o", buff);
        fct_chk(buff_len == 5);
        jw_data_free(buff);
        fct_chk(jw_jid_unescape_localpart("\\3cscript\\3ealert(\\22\\27hi\\27\\22)\\20\\3c\\2fscript\\3e\\26\\3a\\40\\", &buff, &buff_len, &err));
        fct_chk_eq_str("<script>alert(\"'hi'\") </script>&:@\\", buff);
        fct_chk(buff_len == 35);
        jw_data_free(buff);
        fct_chk(jw_jid_unescape_localpart("\\3cscript\\3ealert(\\22\\27hi\\27\\22)\\20\\3c\\2fscript\\3e\\26\\3a\\40\\5c", &buff, &buff_len, &err));
        fct_chk_eq_str("<script>alert(\"'hi'\") </script>&:@\\", buff);
        fct_chk(buff_len == 35);
        jw_data_free(buff);

        fct_chk(jw_jid_unescape_localpart("bагиф\\20\\20cәмәдоғлу", &buff, &buff_len, &err));
        fct_chk(buff_len == 28);
        fct_chk_eq_str("bагиф  cәмәдоғлу", buff);
        jw_data_free(buff);

        fct_chk(jw_jid_unescape_localpart("する\\5c\\22特", &buff, NULL, &err));
        fct_chk_eq_str("する\\\"特", buff);
        jw_data_free(buff);

        fct_chk(jw_jid_unescape_localpart("foo\\q\\q\\q", &buff, &buff_len, &err));
        fct_chk_eq_str("foo\\q\\q\\q", buff);
        jw_data_free(buff);

        fct_chk(jw_jid_unescape_localpart(NULL, &buff, &buff_len, &err));
        fct_chk(!buff);
        fct_chk(!buff_len);
    } FCT_TEST_END()

    FCT_TEST_BGN(jw_jid_cmp)
    {
        jw_jid     *jid, *lessjid;
        jw_err     err;
        jw_jid_ctx *ctx;

        fct_req(jw_jid_context_create(0, &ctx, &err));
        /* compare NULL */
        fct_chk(jw_jid_cmp(NULL, NULL) == 0);
        fct_chk(jw_jid_create_by_parts(ctx, "foo1", "bar1", "baz1", &jid, NULL));
        fct_chk(jw_jid_cmp(jid, NULL) > 0);
        fct_chk(jw_jid_cmp(NULL, jid) < 0);
        fct_chk(jw_jid_create(ctx, "foo1@bar1/baz1", &lessjid, NULL));
        fct_chk(jw_jid_cmp(jid, lessjid) == 0);
        fct_chk(jw_jid_cmp(jid, jw_jid_get_bare_jid(lessjid)) > 0);
        fct_chk(jw_jid_cmp(jw_jid_get_bare_jid(jid), lessjid) < 0);
        jw_jid_destroy(lessjid);

        /* compare < > domains */
        fct_chk(jw_jid_create(ctx, "foo1@bar0/baz1", &lessjid, NULL));
        fct_chk(jw_jid_cmp(jid, lessjid) > 0);
        fct_chk(jw_jid_cmp(lessjid, jid) < 0);
        jw_jid_destroy(lessjid);

        /* localpart */
        fct_chk(jw_jid_create(ctx, "foo0@bar1/baz1", &lessjid, NULL));
        fct_chk(jw_jid_cmp(jid, lessjid) > 0);
        fct_chk(jw_jid_cmp(lessjid, jid) < 0);
        jw_jid_destroy(lessjid);
        fct_chk(jw_jid_create(ctx, "bar1/baz1", &lessjid, NULL));
        fct_chk(jw_jid_cmp(jid, lessjid) > 0);
        fct_chk(jw_jid_cmp(lessjid, jid) < 0);
        jw_jid_destroy(lessjid);

        /* resource */
        fct_chk(jw_jid_create(ctx, "foo1@bar1/baz0", &lessjid, NULL));
        fct_chk(jw_jid_cmp(jid, lessjid) > 0);
        fct_chk(jw_jid_cmp(lessjid, jid) < 0);
        jw_jid_destroy(lessjid);
        fct_chk(jw_jid_create(ctx, "foo1@bar1", &lessjid, NULL));
        fct_chk(jw_jid_cmp(jid, lessjid) > 0);
        fct_chk(jw_jid_cmp(lessjid, jid) < 0);
        jw_jid_destroy(lessjid);

        /* bare to full */
        fct_chk(jw_jid_create(ctx, "bar1", &lessjid, NULL));
        fct_chk(jw_jid_cmp(jid, lessjid) > 0);
        fct_chk(jw_jid_cmp(lessjid, jid) < 0);
        jw_jid_destroy(lessjid);
        jw_jid_destroy(jid);

        jw_jid_context_destroy(ctx);
    } FCT_TEST_END()

#ifndef JABBERWERX_STRINGPREP_ASCII
    FCT_TEST_BGN(jw_jid_valid_unicode)
    {
        fct_chk(jw_jid_valid("志翔志翔志翔志翔志翔志翔志翔志翔志翔志翔志"));
        fct_chk(jw_jid_valid("志翔志翔志翔志翔志翔志翔志翔志翔志翔志翔志.志翔志翔志翔志翔志翔志翔志翔志翔志翔志翔志.志翔志翔志翔志翔志翔志翔志翔志翔志翔志翔志.志翔志翔志翔志翔志翔志翔志翔志翔志翔志翔志.志翔志翔志翔志翔志翔志翔志翔志翔志翔志翔志.志翔志翔志翔志翔志翔志翔志翔志翔志翔志翔志.志翔志翔志翔志翔志翔志翔志翔志翔志翔志翔志"));
        fct_chk(jw_jid_valid("базирана@върху/отделни"));
        fct_chk(jw_jid_valid("базирана/върху@отделни"));

        // negative test
        fct_chk(!jw_jid_valid("志翔志翔志翔志翔志翔志翔志翔志翔志翔志翔志翔"));
        fct_chk(!jw_jid_valid("志.志.志.志.志.志.志.志.志.志.志.志.志.志.志.志.志.志.志.志.志.志.志.志.志.志.志.志.志.志.志.志.志.志.志.志.志"));
        fct_chk(!jw_jid_valid("@базирана@върху/отделни"));
        fct_chk(!jw_jid_valid("базирана/"));
        fct_chk(!jw_jid_valid("базирана@върху/"));
        fct_chk(!jw_jid_valid("базирана@"));
        fct_chk(!jw_jid_valid("базирана@@"));
    } FCT_TEST_END()

    FCT_TEST_BGN(jw_jid_create_unicode)
    {
        jw_jid     *jid, *bjid;
        jw_err     err;
        jw_jid_ctx *ctx;

        fct_req(jw_jid_context_create(0, &ctx, &err));

        // UTF8 encoded jids
        char* utf8_localpart1 = "bагиф\\20cәмәдоғлу";
        char* utf8_domain1 = "aзәрбајҹан";
        char* utf8_resource1 = "Əliyev Heydər";
        char* utf8_barejid = "bагиф\\20cәмәдоғлу@aзәрбајҹан";
        char* utf8_fulljid = "bагиф\\20cәмәдоғлу@aзәрбајҹан/Əliyev Heydər";
        fct_chk(jw_jid_create_by_parts(ctx, utf8_localpart1, utf8_domain1, utf8_resource1, &jid, NULL));
        fct_chk_eq_str(jw_jid_get_localpart(jid), utf8_localpart1);
        fct_chk_eq_str(jw_jid_get_domain(jid), utf8_domain1);
        fct_chk_eq_str(jw_jid_get_resource(jid), utf8_resource1);
        fct_chk_eq_str(jw_jid_get_bare(jid), utf8_barejid);
        fct_chk_eq_str(jw_jid_get_full(jid), utf8_fulljid);
        bjid = jw_jid_get_bare_jid(jid);
        fct_chk(jid != bjid);
        fct_chk_eq_str(jw_jid_get_localpart(bjid), utf8_localpart1);
        fct_chk_eq_str(jw_jid_get_domain(bjid), utf8_domain1);
        fct_chk(jw_jid_get_resource(bjid) == NULL);
        fct_chk_eq_str(jw_jid_get_bare(bjid), utf8_barejid);
        fct_chk_eq_str(jw_jid_get_full(bjid), utf8_barejid);
        jw_jid_destroy(jid);
        jw_jid_destroy(bjid);
        // 3 byte and 4bytes characters
        char *utf8_localpart2 = "சாப்பிடுவேன்";
        char *utf8_domain2 = "foo.com";
        char *utf8_resource2 = "我能吞下玻璃而不傷";
        char *utf8_fulljid2 = "சாப்பிடுவேன்"
                              "@foo.com/"
                              "我能吞下玻璃而不傷";
        char *utf8_barejid2 = "சாப்பிடுவேன்"
                              "@foo.com";
        fct_chk(jw_jid_create(ctx, utf8_fulljid2, &jid, NULL));
        fct_chk_eq_str(jw_jid_get_localpart(jid), utf8_localpart2);
        fct_chk_eq_str(jw_jid_get_domain(jid), utf8_domain2);
        fct_chk_eq_str(jw_jid_get_resource(jid), utf8_resource2);
        fct_chk_eq_str(jw_jid_get_bare(jid), utf8_barejid2);
        fct_chk_eq_str(jw_jid_get_full(jid), utf8_fulljid2);
        bjid = jw_jid_get_bare_jid(jid);
        fct_chk(jid != bjid);
        fct_chk_eq_str(jw_jid_get_localpart(bjid), utf8_localpart2);
        fct_chk_eq_str(jw_jid_get_domain(bjid), utf8_domain2);
        fct_chk(jw_jid_get_resource(bjid) == NULL);
        fct_chk_eq_str(jw_jid_get_bare(bjid), utf8_barejid2);
        fct_chk_eq_str(jw_jid_get_full(bjid), utf8_barejid2);
        jw_jid_destroy(bjid);
        jw_jid_destroy(jid);
        // negative tests
        jid = NULL;
        fct_chk(!jw_jid_create(ctx, "@базирана@върху/отделни", &jid, &err));
        fct_chk(err.code == JW_ERR_INVALID_ARG);
        fct_chk(jid == NULL);
        fct_chk(!jw_jid_create(ctx, "базирана/", &jid, &err));
        fct_chk(err.code == JW_ERR_INVALID_ARG);
        fct_chk(jid == NULL);
        fct_chk(!jw_jid_create(ctx, "базирана@върху/",&jid, &err));
        fct_chk(err.code == JW_ERR_INVALID_ARG);
        fct_chk(jid == NULL);
        fct_chk(!jw_jid_create(ctx, "базирана@", &jid, &err));
        fct_chk(err.code == JW_ERR_INVALID_ARG);
        fct_chk(jid == NULL);
        fct_chk(!jw_jid_create(ctx, "базирана@@", &jid, &err));
        fct_chk(err.code == JW_ERR_INVALID_ARG);
        fct_chk(jid == NULL);
        jw_jid_context_destroy(ctx);
    } FCT_TEST_END()

    FCT_TEST_BGN(jw_jid_create_by_parts_unicode)
    {
        jw_jid *jid, *bjid;
        jw_err err;
        jw_jid_ctx *ctx;

        fct_req(jw_jid_context_create(0, &ctx, &err));
        // utf8 tests replicated as parts
        fct_chk(jw_jid_create_by_parts(ctx, "базирана", "върху", "отделни", &jid, &err));
        fct_chk(jid != NULL);
        fct_chk_eq_str(jw_jid_get_localpart(jid), "базирана");
        fct_chk_eq_str(jw_jid_get_domain(jid), "върху");
        fct_chk_eq_str(jw_jid_get_resource(jid), "отделни");
        fct_chk_eq_str(jw_jid_get_bare(jid), "базирана@върху");
        fct_chk_eq_str(jw_jid_get_full(jid), "базирана@върху/отделни");
        bjid = jw_jid_get_bare_jid(jid);
        fct_chk(jid != bjid);
        fct_chk_eq_str(jw_jid_get_localpart(bjid), "базирана");
        fct_chk_eq_str(jw_jid_get_domain(bjid), "върху");
        fct_chk(jw_jid_get_resource(bjid) == NULL);
        fct_chk_eq_str(jw_jid_get_bare(bjid), "базирана@върху");
        fct_chk_eq_str(jw_jid_get_full(bjid), "базирана@върху");
        jw_jid_destroy(jid);
        jw_jid_destroy(bjid);

        fct_chk(!jw_jid_create_by_parts(ctx, NULL, "базирана/върху", "отделни", &jid, &err));
        jid = NULL;
        fct_chk(jw_jid_create_by_parts(ctx, NULL, "базирана", "върху/отделни", &jid, &err));
        fct_chk(jid != NULL);
        fct_chk_eq_str(jw_jid_get_localpart(jid), NULL);
        fct_chk_eq_str(jw_jid_get_domain(jid), "базирана");
        fct_chk_eq_str(jw_jid_get_resource(jid), "върху/отделни");
        fct_chk_eq_str(jw_jid_get_bare(jid), "базирана");
        fct_chk_eq_str(jw_jid_get_full(jid), "базирана/върху/отделни");
        bjid = jw_jid_get_bare_jid(jid);
        fct_chk(jid != bjid);
        fct_chk_eq_str(jw_jid_get_localpart(bjid), NULL);
        fct_chk_eq_str(jw_jid_get_domain(bjid), "базирана");
        fct_chk(jw_jid_get_resource(bjid) == NULL);
        fct_chk_eq_str(jw_jid_get_bare(bjid), "базирана");
        fct_chk_eq_str(jw_jid_get_full(bjid), "базирана");
        jw_jid_destroy(jid);
        jw_jid_destroy(bjid);
        // 3 byte and 4bytes characters
        char *utf8_localpart2 = "சாப்பிடுவேன்";
        char *utf8_domain2 = "foo.com";
        char *utf8_resource2 = "我能吞下玻璃而不傷";
        char *utf8_fulljid2 = "சாப்பிடுவேன்"
                              "@foo.com/"
                              "我能吞下玻璃而不傷";
        char *utf8_barejid2 = "சாப்பிடுவேன்"
                              "@foo.com";
        fct_chk(jw_jid_create_by_parts(ctx, utf8_localpart2, utf8_domain2, utf8_resource2, &jid, NULL));
        fct_chk_eq_str(jw_jid_get_localpart(jid), utf8_localpart2);
        fct_chk_eq_str(jw_jid_get_domain(jid), utf8_domain2);
        fct_chk_eq_str(jw_jid_get_resource(jid), utf8_resource2);
        fct_chk_eq_str(jw_jid_get_bare(jid), utf8_barejid2);
        fct_chk_eq_str(jw_jid_get_full(jid), utf8_fulljid2);
        bjid = jw_jid_get_bare_jid(jid);
        fct_chk(jid != bjid);
        fct_chk_eq_str(jw_jid_get_localpart(bjid), utf8_localpart2);
        fct_chk_eq_str(jw_jid_get_domain(bjid), utf8_domain2);
        fct_chk(jw_jid_get_resource(bjid) == NULL);
        fct_chk_eq_str(jw_jid_get_bare(bjid), utf8_barejid2);
        fct_chk_eq_str(jw_jid_get_full(bjid), utf8_barejid2);
        jw_jid_destroy(jid);
        jw_jid_destroy(bjid);

        jw_jid_context_destroy(ctx);
    } FCT_TEST_END()

    FCT_TEST_BGN(jw_jid_cmp_unicode)
    {
        jw_jid     *jid, *lessjid;
        jw_err     err;
        jw_jid_ctx *ctx;

        fct_req(jw_jid_context_create(0, &ctx, &err));
        // utf-8 comparisons
        char* utf8_localpart1 = "Bагиф\\20Cәмәдоғлу";
        char* utf8_domain1 = "bзәрбајҹан";
        char* utf8_resource1 = "Əliyev Heydər";
        // 2 < 1 note one char switched in following
        char* utf8_localpart2 = "Bагиф\\20Cәмдәоғлу";
        char* utf8_domain2 = "bзәрабјҹан";
        char* utf8_resource2 = "Əliyev Hedyər";

        fct_chk(jw_jid_create_by_parts(ctx, utf8_localpart1, utf8_domain1, utf8_resource1, &jid, NULL));
        // barejid and same ref
        fct_chk(jw_jid_cmp(jid, NULL) > 0);
        fct_chk(jw_jid_cmp(NULL, jid) < 0);
        fct_chk(jw_jid_cmp(jw_jid_get_bare_jid(jid), jid) < 0);
        fct_chk(jw_jid_cmp(jid, jw_jid_get_bare_jid(jid)) > 0);
        lessjid = jw_jid_copy(jid);
        fct_chk(jw_jid_cmp(lessjid, NULL) > 0);
        fct_chk(jw_jid_cmp(NULL, lessjid) < 0);
        fct_chk(jw_jid_cmp(jid, lessjid) == 0);
        fct_chk(jw_jid_cmp(jid, jw_jid_get_bare_jid(lessjid)) > 0);
        fct_chk(jw_jid_cmp(jw_jid_get_bare_jid(jid), lessjid) < 0);
        jw_jid_destroy(lessjid);

        // domain
        fct_chk(jw_jid_create_by_parts(ctx, utf8_localpart1, utf8_domain2, utf8_resource1, &lessjid, NULL));
        fct_chk(jw_jid_cmp(jid, lessjid) > 0);
        fct_chk(jw_jid_cmp(lessjid, jid) < 0);
        jw_jid_destroy(lessjid);
        fct_chk(jw_jid_create_by_parts(ctx, NULL, utf8_domain1, NULL, &lessjid, NULL));
        fct_chk(jw_jid_cmp(jid, lessjid) > 0);
        fct_chk(jw_jid_cmp(lessjid, jid) < 0);
        jw_jid_destroy(lessjid);

        // localpart
        fct_chk(jw_jid_create_by_parts(ctx, utf8_localpart2, utf8_domain1, utf8_resource1, &lessjid, NULL));
        fct_chk(jw_jid_cmp(jid, lessjid) > 0);
        fct_chk(jw_jid_cmp(lessjid, jid) < 0);
        jw_jid_destroy(lessjid);
        fct_chk(jw_jid_create_by_parts(ctx, NULL, utf8_domain1, utf8_resource1, &lessjid, NULL));
        fct_chk(jw_jid_cmp(jid, lessjid) > 0);
        fct_chk(jw_jid_cmp(lessjid, jid) < 0);
        jw_jid_destroy(lessjid);

        // resource
        fct_chk(jw_jid_create_by_parts(ctx, utf8_localpart1, utf8_domain1, utf8_resource2, &lessjid, NULL));
        fct_chk(jw_jid_cmp(jid, lessjid) > 0);
        fct_chk(jw_jid_cmp(lessjid, jid) < 0);
        jw_jid_destroy(lessjid);
        fct_chk(jw_jid_create_by_parts(ctx, utf8_localpart1, utf8_domain1, NULL, &lessjid, NULL));
        fct_chk(jw_jid_cmp(jid, lessjid) > 0);
        fct_chk(jw_jid_cmp(lessjid, jid) < 0);
        jw_jid_destroy(lessjid);
        jw_jid_destroy(jid);

        jw_jid_context_destroy(ctx);
    } FCT_TEST_END()

    FCT_TEST_BGN(jw_jid_create_by_parts_limits_unicode)
    {
        jw_jid     *jid;
        jw_jid_ctx *ctx;

        static char nullablePattern[] = { (char)0xe1, (char)0xa0, (char)0x86 };

        char str255[256];
        char str256bad[257];
        char str256good[257];
        char str1023[1024];
        char str1024bad[1025];
        char str1024good[1025];

        memset(str255, 'A', 255);
        memset(str256bad, 'A', 256);
        memset(str256good, 'A', 253);
        memcpy(&str256good[253], nullablePattern, 3);
        memset(str1023, 'A', 1023);
        memset(str1024bad, 'A', 1024);
        memset(str1024good, 'A', 1021);
        memcpy(&str1024good[1021], nullablePattern, 3);
        // add in label separators to make "valid" hostnames
        for (int idx = 25; 225 >= idx; ++idx)
        {
            if (0 == idx % 25)
            {
                str255[idx] = str256bad[idx] = str256good[idx] = '.';
            }
        }
        str255[255] = 0;
        str256bad[256] = 0;
        str256good[256] = 0;
        str1023[1023] = 0;
        str1024bad[1024] = 0;
        str1024good[1024] = 0;

        fct_req(jw_jid_context_create(0, &ctx, NULL));
        fct_chk(jw_jid_create_by_parts(ctx, str1023, str255, str1023, &jid, NULL));
        jw_jid_destroy(jid);

        // test individual field limits
        fct_chk(!jw_jid_create_by_parts(ctx, str1024bad, str255, str1023, &jid, NULL));
        fct_chk(!jw_jid_create_by_parts(ctx, str1023, str256bad, str1023, &jid, NULL));
        fct_chk(!jw_jid_create_by_parts(ctx, str1023, str255, str1024bad, &jid, NULL));
        jid = NULL;
        fct_chk(jw_jid_create_by_parts(ctx, str1024good, str255, str1023, &jid, NULL));
        if (NULL != jid) { jw_jid_destroy(jid); jid = NULL; }
        fct_chk(jw_jid_create_by_parts(ctx, str1023, str256good, str1023, &jid, NULL));
        if (NULL != jid) { jw_jid_destroy(jid); jid = NULL; }
        fct_chk(jw_jid_create_by_parts(ctx, str1023, str255, str1024good, &jid, NULL));
        if (NULL != jid) { jw_jid_destroy(jid); }
        jw_jid_context_destroy(ctx);
    } FCT_TEST_END()
#else
    FCT_TEST_BGN(jw_jid_valid_unicode_not_allowed)
    {
        fct_chk(!jw_jid_valid("базирана@върху/отделни"));
        fct_chk(!jw_jid_valid("базирана/върху@отделни"));
    } FCT_TEST_END()

    FCT_TEST_BGN(jw_jid_create_unicode_not_allowed)
    {
        jw_jid     *jid;
        jw_err     err;
        jw_jid_ctx *ctx;

        fct_req(jw_jid_context_create(0, &ctx, &err));
        fct_chk(!jw_jid_create(ctx,
                              "bагиф\\20cәмәдоғлу@aзәрбајҹан/Əliyev Heydər",
                              &jid, &err));
        fct_chk(err.code == JW_ERR_INVALID_ARG);
        jw_jid_context_destroy(ctx);
    } FCT_TEST_END()
    #endif

    FCT_TEST_BGN(jw_jid_overflow)
    {
        jw_jid     *jid;
        jw_jid_ctx *ctx;

        char str8191[8192];
        memset(str8191, 'A', 8191);
        str8191[8191] = 0;

        fct_req(jw_jid_context_create(0, &ctx, NULL));
        fct_chk(!jw_jid_create_by_parts(ctx, str8191, str8191, str8191, &jid, NULL));
        jw_jid_context_destroy(ctx);
    } FCT_TEST_END()
} FCTMF_SUITE_END()
