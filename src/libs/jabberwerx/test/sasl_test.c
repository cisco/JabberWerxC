/**
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

#include "test_utils.h"
#include "../src/include/sasl_int.h"
#include <fct.h>
#include <jabberwerx/util/base64.h>
#include <jabberwerx/util/log.h>
#include <jabberwerx/util/str.h>
#include <jabberwerx/sasl_factory.h>
#include <jabberwerx/client.h>


static int _mallocCnt = 0;
static void *_sasl_test_malloc(size_t size)
{
    ++_mallocCnt;
    return malloc(size);
}

static void *_sasl_test_realloc(void *ptr, size_t size)
{
    if (NULL == ptr)
    {
        return _sasl_test_malloc(size);
    }
    return realloc(ptr, size);
}

static int _freeCnt = 0;
static void _sasl_test_free(void *ptr)
{
    if (NULL == ptr)
    {
        return;
    }
    ++_freeCnt;
    free(ptr);
}

static void _init_memory_funcs()
{
    _mallocCnt = 0;
    _freeCnt = 0;
    jw_data_set_memory_funcs(_sasl_test_malloc, _sasl_test_realloc, _sasl_test_free);
}

static void _uninit_memory_funcs()
{
    jw_data_set_memory_funcs(NULL, NULL, NULL);
}

static bool _init_factory(jw_sasl_factory **factory, jw_err *err)
{
    if (!jw_sasl_factory_create(NULL, factory, err))
    {
        return false;
    }

    jw_sasl_mech *mech_plain;
    if (!jw_sasl_mech_plain_create(NULL, &mech_plain, err))
    {
        jw_sasl_factory_destroy(*factory);
        return false;
    }
    if (!jw_sasl_factory_add_mech(*factory, mech_plain, err))
    {
        jw_sasl_mech_destroy(mech_plain);
        jw_sasl_factory_destroy(*factory);
        return false;
    }

    return true;
}

static bool _bad_init(
                jw_sasl_mech_instance *instance, jw_htable *config, jw_err *err)
{
    UNUSED_PARAM(instance);
    UNUSED_PARAM(config);

    JABBERWERX_ERROR(err, JW_ERR_INVALID_STATE);
    return false;
}

static bool _dummy_evaluate_start(
                        jw_sasl_mech_instance *instance,
                        uint8_t              *in,
                        size_t                in_len,
                        jw_sasl_mech_cdata_evaluate_complete_fn cb,
                        jw_err               *err)
{
    UNUSED_PARAM(instance);
    UNUSED_PARAM(in);
    UNUSED_PARAM(in_len);
    UNUSED_PARAM(err);

    assert(NULL == in);

    cb(instance, NULL, 0, false, false, JW_SASL_ERR_NONE);

    return true;
}

static bool _next_done = true;
static bool _error_returning_evaluate(
                        jw_sasl_mech_instance *instance,
                        uint8_t              *in,
                        size_t                in_len,
                        jw_sasl_mech_cdata_evaluate_complete_fn cb,
                        jw_err               *err)
{
    UNUSED_PARAM(instance);
    UNUSED_PARAM(in_len);
    UNUSED_PARAM(err);

    assert(in);

    jw_log(JW_LOG_TRACE, "converting '%s' to a sasl_error", in);

    jw_sasl_error sasl_err = atoi((char *)in);

    // string is space-terminated
    cb(instance, in, strchr((char *)in, ' ') - (char *)in,
       true, _next_done, sasl_err);

    return true;
}

static bool _bad_out_text_evaluate(
                        jw_sasl_mech_instance *instance,
                        uint8_t              *in,
                        size_t                in_len,
                        jw_sasl_mech_cdata_evaluate_complete_fn cb,
                        jw_err               *err)
{
    UNUSED_PARAM(instance);
    UNUSED_PARAM(in_len);
    UNUSED_PARAM(err);

    if (in)
    {
        jw_data_free(in);
    }

    uint8_t *badutf = (uint8_t *)jw_data_strdup("\x80");
    cb(instance, badutf, 1, false, false, JW_SASL_ERR_NONE);

    return true;
}

static bool _async_evaluate(
                        jw_sasl_mech_instance *instance,
                        uint8_t              *in,
                        size_t                in_len,
                        jw_sasl_mech_cdata_evaluate_complete_fn cb,
                        jw_err               *err)
{
    UNUSED_PARAM(instance);
    UNUSED_PARAM(in_len);
    UNUSED_PARAM(cb);
    UNUSED_PARAM(err);

    if (in)
    {
        jw_data_free(in);
    }

    // doesn't call callback

    return true;
}

static bool _failing_evaluate(
                        jw_sasl_mech_instance *instance,
                        uint8_t              *in,
                        size_t                in_len,
                        jw_sasl_mech_cdata_evaluate_complete_fn cb,
                        jw_err               *err)
{
    UNUSED_PARAM(instance);
    UNUSED_PARAM(in);
    UNUSED_PARAM(in_len);
    UNUSED_PARAM(cb);
    UNUSED_PARAM(err);

    return false;
}

typedef struct _eval_complete_data_int
{
    jw_dom_node *expected_out;
    bool              out_matched;
    bool              done;
    jw_sasl_error     sasl_err;
} *_eval_complete_data;

static void _dummy_evaluate_complete(
                        jw_sasl_mech_instance *instance,
                        jw_dom_node           *out_auth_node,
                        bool                  done,
                        jw_sasl_error         sasl_err,
                        void                 *arg)
{
    UNUSED_PARAM(instance);

    _eval_complete_data data = arg;

    jw_log_dom(JW_LOG_DEBUG, out_auth_node, "out_auth_node: ");

    if (data && data->expected_out)
    {
        jw_log_dom(JW_LOG_DEBUG, data->expected_out, "expected: ");

        data->out_matched = _dom_equal(data->expected_out, out_auth_node, true);

        jw_log(JW_LOG_DEBUG, "out matched: %s",
               data->out_matched ? "true" : "false");
    }

    if (data)
    {
        data->done       = done;
        data->sasl_err = sasl_err;
    }

    jw_log(JW_LOG_DEBUG, "done=%s; sasl_error=%d",
           done ? "true" : "false", sasl_err);
}

static bool _sasl_mech_test(jw_sasl_mech *mech, jw_htable *config,
                            jw_dom_node *in, _eval_complete_data data,
                            jw_sasl_error result, jw_err *err)
{
    bool ret = false;

    jw_sasl_mech_instance *instance = NULL;
    if (!jw_sasl_mech_instance_create(config, mech, &instance, err))
    {
        jw_log(JW_LOG_WARN, "failed to create mech instance");
        goto _sasl_plain_test_fail_label;
    }

    jw_sasl_mech_evaluate_complete_fn cb = _dummy_evaluate_complete;
    if (!jw_sasl_mech_instance_evaluate(instance, NULL, cb, data, err))
    {
        jw_log(JW_LOG_WARN, "failed first mech instance evaluate");
        goto _sasl_plain_test_fail_label;
    }

    if (JW_SASL_ERR_NONE != data->sasl_err || data->done || !data->out_matched)
    {
        jw_log(JW_LOG_WARN, "detected failure in completion callback");
        goto _sasl_plain_test_fail_label;
    }

    if (!jw_sasl_mech_instance_evaluate(instance, in, cb, data, err))
    {
        jw_log(JW_LOG_WARN, "failed second mech instance evaluate");
        jw_dom_context_destroy(jw_dom_get_context(in));
        goto _sasl_plain_test_fail_label;
    }

    if (result != data->sasl_err || !data->done)
    {
        jw_log(JW_LOG_WARN, "unexpected evaluate result");
        goto _sasl_plain_test_fail_label;
    }

    ret = true;

_sasl_plain_test_fail_label:
    if (NULL != instance)
    {
        jw_sasl_mech_instance_destroy(instance);
    }
    return ret;
}

static jw_dom_node *_make_success_node()
{
    jw_dom_ctx *ctx;
    if (!jw_dom_context_create(&ctx, NULL))
    {
        return NULL;
    }

    jw_dom_node *ret;
    if (!jw_dom_element_create(ctx, SASL_SUCCESS, &ret, NULL))
    {
        jw_dom_context_destroy(ctx);
        return NULL;
    }

    return ret;
}

static jw_dom_node *_make_failure_node(jw_sasl_error sasl_err)
{
    jw_dom_ctx *ctx;
    if (!jw_dom_context_create(&ctx, NULL))
    {
        return NULL;
    }

    jw_dom_node *ret;
    if (!jw_dom_element_create(ctx, SASL_FAILURE, &ret, NULL))
    {
        jw_dom_context_destroy(ctx);
        return NULL;
    }

    const char *reason_ename;
    switch (sasl_err)
    {
    case JW_SASL_ERR_NONE:
        reason_ename = "{" SASL_URI "}none";
        break;
    case JW_SASL_ERR_ABORTED:
        reason_ename = SASL_ERR_ABORTED;
        break;
    case JW_SASL_ERR_ACCOUNT_DISABLED:
        reason_ename = SASL_ERR_ACCOUNT_DISABLED;
        break;
    case JW_SASL_ERR_CREDENTIALS_EXPIRED:
        reason_ename = SASL_ERR_CREDENTIALS_EXPIRED;
        break;
    case JW_SASL_ERR_ENCRYPTION_REQUIRED:
        reason_ename = SASL_ERR_ENCRYPTION_REQUIRED;
        break;
    case JW_SASL_ERR_INCORRECT_ENCODING:
        reason_ename = SASL_ERR_INCORRECT_ENCODING;
        break;
    case JW_SASL_ERR_INVALID_AUTHZID:
        reason_ename = SASL_ERR_INVALID_AUTHZID;
        break;
    case JW_SASL_ERR_INVALID_MECHANISM:
        reason_ename = SASL_ERR_INVALID_MECHANISM;
        break;
    case JW_SASL_ERR_MALFORMED_REQUEST:
        reason_ename = SASL_ERR_MALFORMED_REQUEST;
        break;
    case JW_SASL_ERR_MECHANISM_TOO_WEAK:
        reason_ename = SASL_ERR_MECHANISM_TOO_WEAK;
        break;
    case JW_SASL_ERR_NOT_AUTHORIZED:
        reason_ename = SASL_ERR_NOT_AUTHORIZED;
        break;
    case JW_SASL_ERR_TEMPORARY_AUTH_FAILURE:
        reason_ename = SASL_ERR_TEMPORARY_AUTH_FAILURE;
        break;
    default:
        jw_log(JW_LOG_ERROR, "unhandled sasl_err: %d", sasl_err);
        assert(false);
        jw_dom_context_destroy(ctx);
        return NULL;
    }

    jw_dom_node *reason;
    if (!jw_dom_element_create(ctx, reason_ename, &reason, NULL))
    {
        jw_dom_context_destroy(ctx);
        return NULL;
    }

    if (!jw_dom_add_child(ret, reason, NULL))
    {
        jw_dom_context_destroy(ctx);
        return NULL;
    }

    return ret;
}

static jw_dom_node *_make_challenge_node(jw_sasl_error contents)
{
    jw_dom_ctx *ctx;
    if (!jw_dom_context_create(&ctx, NULL))
    {
        return NULL;
    }

    jw_dom_node *ret;
    if (!jw_dom_element_create(ctx, SASL_CHALLENGE, &ret, NULL))
    {
        jw_dom_context_destroy(ctx);
        return NULL;
    }

    uint8_t text[UINT32_MAX_WIDTH + 1];
    int text_len;
    // append a space after the integer so atoi can parse it later without
    // overrunning the base64-decoded buffer (which is not NULL-terminated)
    if (0 >= (text_len =
                snprintf((char *)text, UINT32_MAX_WIDTH, "%u ", contents)))
    {
        jw_dom_context_destroy(ctx);
        return NULL;
    }

    char *encoded_text;
    if (!jw_base64_encode(text, (size_t)text_len, &encoded_text, NULL, NULL))
    {
        jw_dom_context_destroy(ctx);
        return NULL;
    }

    jw_dom_node *text_node;
    if (!jw_dom_text_create(ctx, encoded_text, &text_node, NULL))
    {
        jw_data_free(encoded_text);
        jw_dom_context_destroy(ctx);
        return NULL;
    }

    jw_data_free(encoded_text);

    if (!jw_dom_add_child(ret, text_node, NULL))
    {
        jw_data_free(encoded_text);
        jw_dom_context_destroy(ctx);
        return NULL;
    }

    return ret;
}

static bool _init_eval_complete_data(
        jw_sasl_mech *mech, const char *text, _eval_complete_data data,
        bool first_init)
{
    if (!first_init && NULL != data->expected_out)
    {
        jw_dom_context_destroy(jw_dom_get_context(data->expected_out));
    }

    data->expected_out = NULL;
    data->done         = true;
    data->out_matched  = false;
    data->sasl_err     = -1;

    if (NULL == mech || NULL == text)
    {
        return true;
    }

    jw_dom_ctx *ctx;
    if (!jw_dom_context_create(&ctx, NULL))
    {
        return false;
    }

    jw_dom_node *out;
    if (!jw_dom_element_create(ctx, SASL_AUTH, &out, NULL))
    {
        jw_dom_context_destroy(ctx);
        return false;
    }

    const char *mech_name = jw_sasl_mech_get_name(mech);
    if (!jw_dom_set_attribute(out, "{}"SASL_MECHANISM_LOCALNAME, mech_name, NULL))
    {
        jw_dom_context_destroy(ctx);
        return false;
    }

    jw_dom_node *text_node;
    if (!jw_dom_text_create(ctx, text, &text_node, NULL))
    {
        jw_dom_context_destroy(ctx);
        return false;
    }

    if (!jw_dom_add_child(out, text_node, NULL))
    {
        jw_dom_context_destroy(ctx);
        return false;
    }

    data->expected_out = out;
    return true;
}

static bool _clean_called = false;
static void _dummy_clean (jw_sasl_mech_instance *instance)
{
    UNUSED_PARAM(instance);
    _clean_called = true;
}


static jw_loglevel _initlevel;
FCTMF_FIXTURE_SUITE_BGN(sasl_test)
{
    FCT_SETUP_BGN()
    {
        _initlevel = jw_log_get_level();
        _init_memory_funcs();
    } FCT_SETUP_END()

    FCT_TEARDOWN_BGN()
    {
        if (_mallocCnt != _freeCnt)
        {
            jw_log(JW_LOG_ERROR,
                   "mem leak detected in %s: mallocCnt=%d; freeCnt=%d",
                   fctkern_ptr__->ns.curr_test_name, _mallocCnt, _freeCnt);
        }
        fct_chk_eq_int(_mallocCnt, _freeCnt);
        _uninit_memory_funcs();
        jw_log_set_level(_initlevel);
    } FCT_TEARDOWN_END()

    FCT_TEST_BGN(sasl_factory_basics)
    {
        //jw_log_set_level(JW_LOG_TRACE);

        jw_sasl_factory *factory;
        jw_err          err;

        fct_req(jw_sasl_factory_create(NULL, &factory, NULL));
        jw_sasl_factory_destroy(factory);

        // OOM test
        OOM_RECORD_ALLOCS(_init_factory(&factory, &err));
        jw_sasl_factory_destroy(factory);
        OOM_TEST_INIT();
        OOM_TEST(&err, _init_factory(&factory, &err));
        OOM_TEST_INIT();
        OOM_TEST(NULL, _init_factory(&factory, NULL));
    } FCT_TEST_END()

    FCT_TEST_BGN(sasl_factory_double_add)
    {
        //jw_log_set_level(JW_LOG_TRACE);

        jw_sasl_factory *factory;
        jw_sasl_mech    *mech_plain;
        jw_err          err;

        fct_req(_init_factory(&factory, NULL));
        fct_req(jw_sasl_mech_plain_create(NULL, &mech_plain, NULL));

        fct_chk(!jw_sasl_factory_add_mech(factory, mech_plain, NULL));
        fct_chk(!jw_sasl_factory_add_mech(factory, mech_plain, &err));

        jw_sasl_mech_destroy(mech_plain);
        jw_sasl_factory_destroy(factory);
    } FCT_TEST_END()

    FCT_TEST_BGN(sasl_factory_get_best_mech_single)
    {
        //jw_log_set_level(JW_LOG_TRACE);

        jw_sasl_factory *factory;
        fct_req(_init_factory(&factory, NULL));

        jw_sasl_mech *mech;
        jw_sasl_mech_fn_table fn_table =
                        { NULL, NULL, _dummy_evaluate_start, NULL };
        fct_req(jw_sasl_mech_create("DUMMY", &fn_table, &mech, NULL));
        fct_req(jw_sasl_factory_add_mech(factory, mech, NULL));
        fct_req(jw_sasl_mech_create("DUMMY2", &fn_table, &mech, NULL));
        fct_req(jw_sasl_factory_add_mech(factory, mech, NULL));

        // test choices dom (no match)
        jw_dom_ctx            *ctx;
        jw_dom_node           *choices;
        jw_dom_node           *bad_choice;
        jw_dom_node           *choice_text;
        jw_sasl_mech_instance *instance = NULL;
        jw_err                err;

        fct_req(jw_dom_context_create(&ctx, NULL));
        fct_req(jw_dom_element_create(ctx, SASL_MECHANISM, &choices, NULL));
        fct_req(jw_dom_text_create(ctx, "nodummy", &choice_text, NULL));
        fct_req(jw_dom_add_child(choices, choice_text, NULL));
        fct_chk(jw_sasl_factory_get_best_mech_in_dom(
                                    factory, choices, NULL, &instance, NULL));
        fct_chk(NULL == instance);

        // test choices dom (mechanism match)
        fct_req(jw_dom_remove_child(choices, choice_text, NULL));
        fct_req(jw_dom_text_create(ctx, "DUMMY", &choice_text, NULL));
        fct_req(jw_dom_add_child(choices, choice_text, NULL));
        fct_req(jw_sasl_factory_get_best_mech_in_dom(
                                    factory, choices, NULL, &instance, NULL));
        fct_req(NULL != instance);
        fct_chk_eq_str("DUMMY", jw_sasl_mech_get_name(jw_sasl_mech_instance_get_mech(instance)));
        jw_sasl_mech_instance_destroy(instance);

        // test choices dom (mechanisms match)
        // include all kinds of bad mechanisms to skip over
        fct_req(jw_dom_element_create(ctx, SASL_MECHANISMS, &choices, NULL));
        fct_req(jw_dom_add_child(choices, jw_dom_get_parent(choice_text), NULL));
        fct_req(jw_dom_element_create(ctx, "{"SASL_URI"}imamech", &bad_choice, NULL));
        fct_req(jw_dom_add_child(choices, bad_choice, NULL));
        fct_req(jw_dom_element_create(ctx, SASL_MECHANISM, &bad_choice, NULL));
        fct_req(jw_dom_add_child(choices, bad_choice, NULL));
        fct_req(jw_dom_text_create(ctx, "DUMMY", &choice_text, NULL));
        fct_req(jw_dom_add_child(choices, choice_text, NULL));
        fct_req(jw_sasl_factory_get_best_mech_in_dom(
                                    factory, choices, NULL, &instance, NULL));
        fct_req(NULL != instance);
        fct_chk_eq_str("DUMMY", jw_sasl_mech_get_name(jw_sasl_mech_instance_get_mech(instance)));
        jw_sasl_mech_instance_destroy(instance);

        // OOM testing
        OOM_RECORD_ALLOCS(jw_sasl_factory_get_best_mech_in_dom(
                                    factory, choices, NULL, &instance, &err));
        jw_sasl_mech_instance_destroy(instance);
        OOM_TEST_INIT();
        OOM_TEST(&err, jw_sasl_factory_get_best_mech_in_dom(
                                    factory, choices, NULL, &instance, &err));
        OOM_TEST_INIT();
        OOM_TEST(NULL, jw_sasl_factory_get_best_mech_in_dom(
                                    factory, choices, NULL, &instance, NULL));

        // test other failure modes
        fct_req(jw_dom_set_attribute(choices, "{"SASL_URI"}ename", "someattrib", NULL));
        fct_chk(!jw_sasl_factory_get_best_mech_in_dom(factory,
                        jw_dom_get_first_attribute(choices), NULL, &instance, NULL));
        fct_chk(!jw_sasl_factory_get_best_mech_in_dom(factory,
                        jw_dom_get_first_attribute(choices), NULL, &instance, &err));

        fct_req(jw_dom_element_create(ctx, "{"SASL_URI"}mech", &choices, NULL));
        fct_chk(!jw_sasl_factory_get_best_mech_in_dom(factory,
                                            choices, NULL, &instance, NULL));
        fct_chk(!jw_sasl_factory_get_best_mech_in_dom(factory,
                                            choices, NULL, &instance, &err));

        jw_dom_context_destroy(ctx);
        jw_sasl_factory_destroy(factory);
    } FCT_TEST_END()

    FCT_TEST_BGN(sasl_factory_get_best_mech_multiple)
    {
        //jw_log_set_level(JW_LOG_TRACE);

        jw_sasl_factory *factory;
        fct_req(_init_factory(&factory, NULL));

        jw_sasl_mech *mech;
        jw_sasl_mech_fn_table fn_table =
                        { NULL, NULL, _dummy_evaluate_start, NULL };
        fct_req(jw_sasl_mech_create("GOOD_DUMMY", &fn_table, &mech, NULL));
        fct_req(jw_sasl_factory_add_mech(factory, mech, NULL));

        fn_table.init_fn = _bad_init;
        fct_req(jw_sasl_mech_create("BAD_DUMMY", &fn_table, &mech, NULL));
        fct_req(jw_sasl_factory_add_mech(factory, mech, NULL));

        // build choices dom with both bad_dummy and plain
        jw_dom_ctx            *ctx;
        jw_dom_node           *choices;
        jw_dom_node           *node;
        jw_dom_node           *text;
        jw_sasl_mech_instance *instance = NULL;

        fct_req(jw_dom_context_create(&ctx, NULL));
        fct_req(jw_dom_element_create(ctx, SASL_MECHANISMS, &choices, NULL));
        fct_req(jw_dom_element_create(ctx, SASL_MECHANISM, &node, NULL));
        fct_req(jw_dom_text_create(ctx, "PLAIN", &text, NULL));
        fct_req(jw_dom_add_child(node, text, NULL));
        fct_req(jw_dom_add_child(choices, node, NULL));
        fct_req(jw_dom_element_create(ctx, SASL_MECHANISM, &node, NULL));
        fct_req(jw_dom_text_create(ctx, "BAD_DUMMY", &text, NULL));
        fct_req(jw_dom_add_child(node, text, NULL));
        fct_req(jw_dom_add_child(choices, node, NULL));
        fct_chk(jw_sasl_factory_get_best_mech_in_dom(
                        factory, choices, (jw_htable*)"mock", &instance, NULL));
        fct_req(NULL != instance);
        fct_chk_eq_str("PLAIN", jw_sasl_mech_get_name(jw_sasl_mech_instance_get_mech(instance)));
        
        jw_sasl_mech_instance_destroy(instance);
        jw_dom_context_destroy(ctx);
        jw_sasl_factory_destroy(factory);
    } FCT_TEST_END()

    FCT_TEST_BGN(sasl_factory_iterate)
    {
        //jw_log_set_level(JW_LOG_TRACE);

        jw_sasl_factory *factory;

        // so we can meaningfully compare against NULL later
        jw_sasl_mech *mech = (jw_sasl_mech*)0x1;

        fct_req(jw_sasl_factory_create(NULL, &factory, NULL));
        jw_sasl_factory_iter iter;
        fct_req(jw_sasl_factory_iter_begin(factory, &iter, NULL));
        fct_req(jw_sasl_factory_iter_next(&iter, &mech, NULL));
        fct_chk(NULL == mech);
        jw_sasl_factory_destroy(factory);

        mech = NULL;
        fct_req(_init_factory(&factory, NULL));
        fct_req(jw_sasl_factory_iter_begin(factory, &iter, NULL));
        fct_req(jw_sasl_factory_iter_next(&iter, &mech, NULL));
        fct_chk_eq_str("PLAIN", jw_sasl_mech_get_name(mech));
        fct_req(jw_sasl_factory_iter_next(&iter, &mech, NULL));
        fct_chk(NULL == mech);

        jw_sasl_mech_fn_table fn_table =
                        { NULL, NULL, _dummy_evaluate_start, NULL };
        fct_req(jw_sasl_mech_create("DUMMY", &fn_table, &mech, NULL));
        fct_req(jw_sasl_factory_add_mech(factory, mech, NULL));
        fct_req(jw_sasl_mech_create("DUMMY2", &fn_table, &mech, NULL));
        fct_req(jw_sasl_factory_add_mech(factory, mech, NULL));
        fct_req(jw_sasl_factory_iter_begin(factory, &iter, NULL));
        fct_req(jw_sasl_factory_iter_next(&iter, &mech, NULL));
        fct_chk_eq_str("DUMMY2", jw_sasl_mech_get_name(mech));
        fct_req(jw_sasl_factory_iter_next(&iter, &mech, NULL));
        fct_chk_eq_str("DUMMY", jw_sasl_mech_get_name(mech));
        fct_req(jw_sasl_factory_iter_next(&iter, &mech, NULL));
        fct_chk_eq_str("PLAIN", jw_sasl_mech_get_name(mech));
        fct_req(jw_sasl_factory_iter_next(&iter, &mech, NULL));
        fct_chk(NULL == mech);

        jw_sasl_factory_destroy(factory);
    } FCT_TEST_END()

    FCT_TEST_BGN(sasl_factory_htable_clean)
    {
        //jw_log_set_level(JW_LOG_TRACE);

        jw_htable       *config;
        jw_sasl_factory *factory;

        fct_req(jw_sasl_factory_create(NULL, &factory, NULL));
        fct_req(jw_htable_create(
                            0, jw_str_hashcode, jw_str_compare, &config, NULL));

        fct_req(jw_htable_put(config, "factory", factory,
                              jw_sasl_factory_htable_cleaner, NULL));
        jw_htable_destroy(config);
    } FCT_TEST_END()

    FCT_TEST_BGN(sasl_bad_mech)
    {
        //jw_log_set_level(JW_LOG_TRACE);

        // test mech_create failure modes
        jw_sasl_mech *mech;
        jw_err       err;
        jw_sasl_mech_fn_table fn_table = { NULL, NULL, NULL, NULL };
        fct_chk(!jw_sasl_mech_create("DUMMY", &fn_table, &mech, NULL));
        fct_chk(!jw_sasl_mech_create("DUMMY", &fn_table, &mech, &err));
        fn_table.evaluate_start_fn = _dummy_evaluate_start;
        fct_chk(!jw_sasl_mech_create("", &fn_table, &mech, NULL));
        fct_chk(!jw_sasl_mech_create("", &fn_table, &mech, &err));

        fct_chk(!jw_sasl_mech_create(";MECH", &fn_table, &mech, NULL));
        fct_chk(!jw_sasl_mech_create("MECH;", &fn_table, &mech, NULL));
        fct_chk(!jw_sasl_mech_create("ME;CH", &fn_table, &mech, NULL));
        fct_chk(!jw_sasl_mech_create("\x01", &fn_table, &mech, NULL));

        char *too_long_name = "MECHAMECHABOBECKABANANAFANAFOFECKA";
        fct_chk(!jw_sasl_mech_create(too_long_name, &fn_table, &mech, NULL));
        fct_chk(!jw_sasl_mech_create(too_long_name, &fn_table, &mech, &err));

        // max chars is 20
        char *long_name = "MECHAMECHABOBECKABAN";
        fct_req(jw_sasl_mech_create(long_name, &fn_table, &mech, NULL));

        jw_sasl_mech_destroy(mech);
    } FCT_TEST_END()

    FCT_TEST_BGN(sasl_mech_instance_null_fn)
    {
        //jw_log_set_level(JW_LOG_TRACE);

        jw_sasl_factory *factory;
        fct_req(_init_factory(&factory, NULL));

        jw_sasl_mech *mech;
        jw_err       err;
        jw_sasl_mech_fn_table fn_table = { NULL, NULL, NULL, NULL };
        fn_table.evaluate_start_fn = _dummy_evaluate_start;
        fn_table.clean_fn          = _dummy_clean;

        _clean_called = false;
        fct_req(jw_sasl_mech_create("DUM-MY", &fn_table, &mech, NULL));
        fct_req(jw_sasl_factory_add_mech(factory, mech, NULL));

        jw_sasl_mech_instance *instance = NULL;
        fct_req(jw_sasl_mech_instance_create(NULL, mech, &instance, NULL));
        fct_chk(!_clean_called);
        jw_sasl_mech_instance_destroy(instance);
        fct_chk(_clean_called);

        // OOM test instance creation
        instance = NULL;
        OOM_RECORD_ALLOCS(jw_sasl_mech_instance_create(NULL, mech, &instance, &err));
        jw_sasl_mech_instance_destroy(instance);
        OOM_TEST_INIT();
        OOM_TEST(&err, jw_sasl_mech_instance_create(NULL, mech, &instance, &err));
        OOM_TEST_INIT();
        OOM_TEST(NULL, jw_sasl_mech_instance_create(NULL, mech, &instance, NULL));

        jw_dom_ctx  *ctx;
        jw_dom_node *choice;
        jw_dom_node *choice_text;

        fct_req(jw_dom_context_create(&ctx, NULL));
        fct_req(jw_dom_element_create(ctx, SASL_MECHANISM, &choice, NULL));
        fct_req(jw_dom_text_create(ctx, "duM-My", &choice_text, NULL));
        fct_req(jw_dom_add_child(choice, choice_text, NULL));
        fct_req(jw_sasl_factory_get_best_mech_in_dom(
                                    factory, choice, NULL, &instance, NULL));
        fct_req(NULL != instance);
        mech = jw_sasl_mech_instance_get_mech(instance);
        fct_chk_eq_str("DUM-MY", jw_sasl_mech_get_name(mech));

        struct _eval_complete_data_int data;
        fct_req(_init_eval_complete_data(NULL, NULL, &data, true));

        jw_dom_ctx *in_ctx = NULL;
        jw_dom_node *in = NULL;
        fct_req(jw_dom_context_create(&in_ctx, NULL));
        fct_req(jw_dom_element_create(in_ctx, SASL_CHALLENGE, &in, NULL));

        jw_sasl_mech_evaluate_complete_fn cb = _dummy_evaluate_complete;
        fct_chk(jw_sasl_mech_instance_evaluate(instance, in, cb, &data, NULL));
        fct_chk_eq_int(JW_SASL_ERR_NONE, data.sasl_err);

        fct_chk(jw_sasl_mech_instance_evaluate(instance, in, cb, &data, NULL));
        fct_chk_neq_int(JW_SASL_ERR_NONE, data.sasl_err);
        jw_sasl_mech_instance_destroy(instance);

        jw_sasl_mech *mech_copy = NULL;
        fct_req(jw_sasl_mech_copy(mech, &mech_copy, NULL));
        fct_chk_eq_str(jw_sasl_mech_get_name(mech), jw_sasl_mech_get_name(mech_copy));
        fct_req(jw_sasl_mech_instance_create(NULL, mech_copy, &instance, NULL));
        fct_chk(jw_sasl_mech_instance_evaluate(instance, in, cb, &data, NULL));
        fct_chk_eq_int(JW_SASL_ERR_NONE, data.sasl_err);

        // give the default evaluator something to free internally
        jw_dom_node *text;
        fct_req(jw_dom_text_create(in_ctx, "MTA=", &text, NULL));
        fct_req(jw_dom_add_child(in, text, NULL));

        fct_chk(jw_sasl_mech_instance_evaluate(instance, in, cb, &data, NULL));
        fct_chk_neq_int(JW_SASL_ERR_NONE, data.sasl_err);

        // OOM test
        OOM_SIMPLE_TEST_NO_CHECK(jw_sasl_mech_instance_evaluate(
                                                instance, in, cb, &data, &err));
        OOM_TEST_INIT();
        OOM_TEST_NO_CHECK(NULL, jw_sasl_mech_instance_evaluate(
                                                instance, in, cb, &data, NULL));

        jw_sasl_mech_instance_destroy(instance);
        jw_sasl_mech_destroy(mech_copy);

        jw_dom_context_destroy(in_ctx);
        _init_eval_complete_data(NULL, NULL, &data, false);
        jw_dom_context_destroy(ctx);
        jw_sasl_factory_destroy(factory);
    } FCT_TEST_END()

    FCT_TEST_BGN(sasl_mech_instance_failure)
    {
        //jw_log_set_level(JW_LOG_TRACE);

        // create mechanism that returns sasl errors on start
        jw_sasl_mech *mech;
        jw_sasl_mech_fn_table fn_table = { NULL, NULL, NULL, NULL };
        fn_table.evaluate_start_fn = _error_returning_evaluate;
        fct_req(jw_sasl_mech_create("ERROR_MECH", &fn_table, &mech, NULL));
        _next_done = true;

        struct _eval_complete_data_int data;
        fct_req(_init_eval_complete_data(NULL, NULL, &data, true));
        jw_sasl_mech_evaluate_complete_fn cb = _dummy_evaluate_complete;

        // ensure all error types are shuttled through properly
        for (jw_sasl_error sasl_err = JW_SASL_ERR_ABORTED;
             JW_SASL_ERR_TEMPORARY_AUTH_FAILURE + 1 >= sasl_err;
             ++sasl_err)
        {
            jw_sasl_mech_instance *instance;
            fct_req(jw_sasl_mech_instance_create(NULL, mech, &instance, NULL));

            jw_dom_node *in = _make_challenge_node(sasl_err);
            fct_req(in);

            fct_req(_init_eval_complete_data(NULL, NULL, &data, false));
            fct_chk(jw_sasl_mech_instance_evaluate(
                                instance, in, cb, &data, NULL));
            fct_chk_eq_int(sasl_err, data.sasl_err);

            jw_dom_context_destroy(jw_dom_get_context(in));
            jw_sasl_mech_instance_destroy(instance);
        }
        jw_sasl_mech_destroy(mech);

        // return various failures to sasl plain
        jw_htable *config;
        fct_req(jw_htable_create(0, jw_str_hashcode, jw_str_compare, &config, NULL));
        fct_req(jw_htable_put(config, JW_CLIENT_CONFIG_USERJID, "alocal@bdomain", NULL, NULL));
        fct_req(jw_htable_put(config, JW_CLIENT_CONFIG_USERPW, "passme", NULL, NULL));

        fct_req(jw_sasl_mech_plain_create(config, &mech, NULL));

        for (jw_sasl_error sasl_err = JW_SASL_ERR_NONE;
             JW_SASL_ERR_TEMPORARY_AUTH_FAILURE + 1 >= sasl_err;
             ++sasl_err)
        {
            jw_sasl_mech_instance *instance;
            fct_req(jw_sasl_mech_instance_create(
                                config, mech, &instance, NULL));

            jw_sasl_error sasl_err_cmp = sasl_err;

            jw_dom_node *in;
            if (JW_SASL_ERR_TEMPORARY_AUTH_FAILURE + 1 == sasl_err)
            {
                // create reason-less failure node
                in = _make_failure_node(JW_SASL_ERR_ABORTED);
                jw_dom_clear_children(in);
                sasl_err_cmp = JW_SASL_ERR_TEMPORARY_AUTH_FAILURE;
            }
            else if (JW_SASL_ERR_NONE == sasl_err)
            {
                in = _make_failure_node(sasl_err);
                sasl_err_cmp = JW_SASL_ERR_TEMPORARY_AUTH_FAILURE;
            }
            else
            {
                in = _make_failure_node(sasl_err);
            }
            fct_req(in);

            fct_req(jw_sasl_mech_instance_evaluate(
                                instance, NULL, cb, NULL, NULL));
            fct_req(_init_eval_complete_data(NULL, NULL, &data, false));
            fct_req(jw_sasl_mech_instance_evaluate(
                                instance, in, cb, &data, NULL));
            fct_chk_eq_int(sasl_err_cmp, data.sasl_err);

            jw_dom_context_destroy(jw_dom_get_context(in));
            jw_sasl_mech_instance_destroy(instance);
        }
        
        jw_sasl_mech_destroy(mech);
        jw_htable_destroy(config);

        jw_err err;
        fn_table.evaluate_start_fn = _async_evaluate;
        fct_req(jw_sasl_mech_create("ASYNC_MECH", &fn_table, &mech, NULL));
        jw_sasl_mech_instance *instance;
        fct_req(jw_sasl_mech_instance_create(NULL, mech, &instance, NULL));

        // call evaluate twice without completing a callback
        fct_req(jw_sasl_mech_instance_evaluate(
                            instance, NULL, cb, NULL, NULL));
        fct_chk(!jw_sasl_mech_instance_evaluate(
                            instance, NULL, cb, NULL, NULL));
        fct_chk(!jw_sasl_mech_instance_evaluate(
                            instance, NULL, cb, NULL, &err));
        fct_chk_eq_int(JW_ERR_INVALID_STATE, err.code);

        jw_sasl_mech_instance_destroy(instance);
        jw_sasl_mech_destroy(mech);
    } FCT_TEST_END()

    FCT_TEST_BGN(sasl_mech_instance_multistep)
    {
        //jw_log_set_level(JW_LOG_TRACE);

        jw_sasl_mech *mech;
        jw_sasl_mech_fn_table fn_table =
           { NULL, NULL, _error_returning_evaluate, _error_returning_evaluate };
        fct_req(jw_sasl_mech_create("MULTI_MECH", &fn_table, &mech, NULL));

        struct _eval_complete_data_int data;
        fct_req(_init_eval_complete_data(NULL, NULL, &data, true));
        jw_sasl_mech_evaluate_complete_fn cb = _dummy_evaluate_complete;

        jw_sasl_mech_instance *instance;
        fct_req(jw_sasl_mech_instance_create(NULL, mech, &instance, NULL));

        jw_dom_node *in = _make_challenge_node(JW_SASL_ERR_NONE);
        fct_req(in);

        // run through a couple challenge-response sequences
        _next_done = false;
        fct_chk(jw_sasl_mech_instance_evaluate(
                            instance, in, cb, &data, NULL));
        fct_chk_eq_int(JW_SASL_ERR_NONE, data.sasl_err);

        fct_req(_init_eval_complete_data(NULL, NULL, &data, false));
        fct_chk(jw_sasl_mech_instance_evaluate(
                            instance, in, cb, &data, NULL));
        fct_chk_eq_int(JW_SASL_ERR_NONE, data.sasl_err);

        _next_done = true;
        fct_req(_init_eval_complete_data(NULL, NULL, &data, false));
        fct_chk(jw_sasl_mech_instance_evaluate(
                            instance, in, cb, &data, NULL));
        fct_chk_eq_int(JW_SASL_ERR_NONE, data.sasl_err);
        jw_sasl_mech_instance_destroy(instance);

        // OOM test
        _next_done = false;
        fct_req(jw_sasl_mech_instance_create(NULL, mech, &instance, NULL));
        fct_req(jw_sasl_mech_instance_evaluate(
                            instance, in, cb, &data, NULL));
        OOM_SIMPLE_TEST_NO_CHECK(jw_sasl_mech_instance_evaluate(
                                                instance, in, cb, &data, &err));
        OOM_TEST_INIT();
        OOM_TEST_NO_CHECK(NULL, jw_sasl_mech_instance_evaluate(
                                                instance, in, cb, &data, NULL));
        jw_sasl_mech_instance_destroy(instance);

        jw_dom_context_destroy(jw_dom_get_context(in));
        jw_sasl_mech_destroy(mech);
    } FCT_TEST_END()

    FCT_TEST_BGN(sasl_mech_instance_bad_in)
    {
        //jw_log_set_level(JW_LOG_TRACE);

        jw_sasl_mech *mech;
        jw_sasl_mech_fn_table fn_table =
                        { NULL, NULL, _failing_evaluate, NULL };
        jw_sasl_mech_evaluate_complete_fn cb = _dummy_evaluate_complete;
        fct_req(jw_sasl_mech_create("-_-", &fn_table, &mech, NULL));

        // test unknown data from server
        jw_sasl_mech_instance *instance;
        fct_req(jw_sasl_mech_instance_create(NULL, mech, &instance, NULL));

        jw_dom_ctx *in_ctx;
        fct_req(jw_dom_context_create(&in_ctx, NULL));

        jw_dom_node *in;
        fct_req(jw_dom_element_create(in_ctx, "{" SASL_URI "}bad", &in, NULL));

        jw_err err;
        fct_chk(!jw_sasl_mech_instance_evaluate(
                            instance, in, cb, NULL, NULL));
        fct_chk(!jw_sasl_mech_instance_evaluate(
                            instance, in, cb, NULL, &err));
        fct_chk_eq_int(JW_ERR_INVALID_ARG, err.code);

        // test bad challenge data from the server
        fct_req(jw_dom_element_create(in_ctx, SASL_CHALLENGE, &in, NULL));

        jw_dom_node *text_node;
        fct_req(jw_dom_text_create(in_ctx, "nonbase64.??{}", &text_node, NULL));
        fct_req(jw_dom_add_child(in, text_node, NULL));

        OOM_SIMPLE_TEST_NO_CHECK(jw_sasl_mech_instance_evaluate(
                                                instance, in, cb, NULL, &err));
        OOM_TEST_INIT();
        OOM_TEST_NO_CHECK(NULL, jw_sasl_mech_instance_evaluate(
                                                instance, in, cb, NULL, NULL));

        jw_dom_context_destroy(in_ctx);
        jw_sasl_mech_instance_destroy(instance);
        jw_sasl_mech_destroy(mech);
    } FCT_TEST_END()

    FCT_TEST_BGN(sasl_bad_mech_instance)
    {
        //jw_log_set_level(JW_LOG_TRACE);

        jw_sasl_mech *mech;
        jw_sasl_mech_fn_table fn_table =
                        { NULL, NULL, _bad_out_text_evaluate, NULL };
        fct_req(jw_sasl_mech_create("FAULTY_MECH", &fn_table, &mech, NULL));

        struct _eval_complete_data_int data;
        fct_req(_init_eval_complete_data(NULL, NULL, &data, true));
        jw_sasl_mech_evaluate_complete_fn cb = _dummy_evaluate_complete;

        jw_sasl_mech_instance *instance;
        fct_req(jw_sasl_mech_instance_create(NULL, mech, &instance, NULL));

        jw_dom_node *in = _make_challenge_node(JW_SASL_ERR_NONE);
        fct_req(in);

        _next_done = false;
        fct_chk(jw_sasl_mech_instance_evaluate(
                            instance, in, cb, &data, NULL));
        fct_chk_eq_int(JW_SASL_ERR_TEMPORARY_AUTH_FAILURE, data.sasl_err);

        jw_dom_context_destroy(jw_dom_get_context(in));
        jw_sasl_mech_instance_destroy(instance);
        jw_sasl_mech_destroy(mech);
    } FCT_TEST_END()

    FCT_TEST_BGN(sasl_plain_happy)
    {
        //jw_log_set_level(JW_LOG_TRACE);

        jw_sasl_mech *mech = NULL;

        fct_req(jw_sasl_mech_plain_create(NULL, &mech, NULL));

        jw_htable *config;
        fct_req(jw_htable_create(0, jw_str_hashcode, jw_str_compare, &config, NULL));
        fct_req(jw_htable_put(config, JW_CLIENT_CONFIG_USERJID, "alocal@bdomain", NULL, NULL));
        fct_req(jw_htable_put(config, JW_CLIENT_CONFIG_USERPW, "passme", NULL, NULL));

        // base64-encoded version of "\0alocal\0passme"
        struct _eval_complete_data_int data;
        fct_req(_init_eval_complete_data(mech, "AGFsb2NhbABwYXNzbWU=", &data, true));

        jw_dom_node *in = _make_success_node();
        fct_req(in);
        OOM_SIMPLE_TEST_NO_CHECK(_sasl_mech_test(mech, config, in,
                                                &data, JW_SASL_ERR_NONE, &err));
        OOM_TEST_INIT();
        OOM_TEST_NO_CHECK(NULL, _sasl_mech_test(mech, config, in,
                                                &data, JW_SASL_ERR_NONE, NULL));

        _init_eval_complete_data(NULL, NULL, &data, false);
        jw_dom_context_destroy(jw_dom_get_context(in));
        jw_sasl_mech_destroy(mech);
        jw_htable_destroy(config);
    } FCT_TEST_END()

    FCT_TEST_BGN(sasl_plain_error)
    {
        //jw_log_set_level(JW_LOG_TRACE);

        jw_err err = { .code = JW_ERR_NONE };

        jw_sasl_mech *mech = NULL;
        fct_req(jw_sasl_mech_plain_create(NULL, &mech, NULL));

        struct _eval_complete_data_int data;
        fct_req(_init_eval_complete_data(NULL, NULL, &data, true));

        // no config
        fct_chk(!_sasl_mech_test(mech, NULL, NULL, &data, JW_SASL_ERR_NONE, NULL));
        fct_chk(!_sasl_mech_test(mech, NULL, NULL, &data, JW_SASL_ERR_NONE, &err));
        fct_chk_eq_int(JW_ERR_INVALID_ARG, err.code);
        err.code = JW_ERR_NONE;

        // unpopulated config
        jw_htable *config;
        fct_req(jw_htable_create(0, jw_str_hashcode, jw_str_compare, &config, NULL));
        fct_chk(!_sasl_mech_test(mech, config, NULL, &data, JW_SASL_ERR_NONE, NULL));
        fct_chk(!_sasl_mech_test(mech, config, NULL, &data, JW_SASL_ERR_NONE, &err));
        fct_chk_eq_int(JW_ERR_INVALID_STATE, err.code);
        err.code = JW_ERR_NONE;

        // missing password
        fct_req(jw_htable_put(config, JW_CLIENT_CONFIG_USERJID, "alocal@bdomain", NULL, NULL));
        fct_chk(!_sasl_mech_test(mech, config, NULL, &data, JW_SASL_ERR_NONE, &err));
        fct_chk_eq_int(JW_ERR_INVALID_STATE, err.code);
        err.code = JW_ERR_NONE;

        // add in a jid context to cover those paths (it works with or without one)
        jw_jid_ctx *jid_ctx;
        fct_req(jw_jid_context_create(0, &jid_ctx, NULL));
        fct_req(jw_htable_put(config, JW_CLIENT_CONFIG_JID_CONTEXT, jid_ctx, NULL, NULL));

        // jid with no localpart
        fct_req(jw_htable_put(config, JW_CLIENT_CONFIG_USERJID, "bdomain", NULL, NULL));
        fct_req(jw_htable_put(config, JW_CLIENT_CONFIG_USERPW, "passme", NULL, NULL));
        fct_chk(!_sasl_mech_test(mech, config, NULL, &data, JW_SASL_ERR_NONE, NULL));
        fct_chk(!_sasl_mech_test(mech, config, NULL, &data, JW_SASL_ERR_NONE, &err));
        fct_chk_eq_int(JW_ERR_INVALID_STATE, err.code);
        err.code = JW_ERR_NONE;

        // base64-encoded version of "\0alocal\0passme"
        fct_req(_init_eval_complete_data(mech, "AGFsb2NhbABwYXNzbWU=", &data, false));

        // missing sasl plain server response
        fct_req(jw_htable_put(config, JW_CLIENT_CONFIG_USERJID, "alocal@bdomain", NULL, NULL));
        fct_chk(!_sasl_mech_test(mech, config, NULL, &data, JW_SASL_ERR_NONE, NULL));
        fct_chk_eq_int(JW_SASL_ERR_TEMPORARY_AUTH_FAILURE, data.sasl_err);

        // server returns failure
        jw_dom_node *in = _make_failure_node(JW_SASL_ERR_NOT_AUTHORIZED);
        fct_req(in);
        fct_chk(_sasl_mech_test(mech, config, in,
                                 &data, JW_SASL_ERR_NOT_AUTHORIZED, &err));
        fct_chk_eq_int(JW_ERR_NONE, err.code);

        jw_dom_context_destroy(jw_dom_get_context(in));
        _init_eval_complete_data(NULL, NULL, &data, false);
        jw_sasl_mech_destroy(mech);
        jw_htable_destroy(config);
        jw_jid_context_destroy(jid_ctx);
    } FCT_TEST_END()

    FCT_TEST_BGN(sasl_external)
    {
        //jw_log_set_level(JW_LOG_TRACE);

        jw_sasl_mech *mech = NULL;

        fct_req(jw_sasl_mech_external_create(NULL, &mech, NULL));

        struct _eval_complete_data_int data;
        fct_req(_init_eval_complete_data(mech, "=", &data, true));

        jw_dom_node *in = _make_success_node();
        fct_req(in);
        fct_chk(_sasl_mech_test(mech, NULL, in, &data, JW_SASL_ERR_NONE, NULL));

        jw_dom_context_destroy(jw_dom_get_context(in));
        fct_req(_init_eval_complete_data(mech, NULL, &data, false));
        jw_sasl_mech_destroy(mech);
    } FCT_TEST_END()
} FCTMF_FIXTURE_SUITE_END()
