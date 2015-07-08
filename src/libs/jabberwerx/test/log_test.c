/**
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

#include "fct.h"

#include <jabberwerx/util/log.h>
#include <jabberwerx/dom.h>

#include "test_utils.h"

#undef JABBERWERX_ERROR
#define JABBERWERX_ERROR(err, errcode) \
{\
    GCC_BEGIN_IGNORED_WARNING(-Waddress); \
        if ((err) != NULL && (errcode) != JW_ERR_NONE) \
        { \
            (err)->code = (errcode); \
            (err)->message = jw_err_message((errcode)); \
            (err)->function = __func__; \
            (err)->file = __FILE__; \
            (err)->line = __LINE__; \
        } \
    GCC_END_IGNORED_WARNING(-Waddress); \
}

typedef struct _log_chunk_int
{
    const char            *chunk;
    size_t                 len;
    jw_data_free_func      free_fn;
    struct _log_chunk_int *cur;
    struct _log_chunk_int *next;
} *_log_chunk;

static jw_loglevel _initlevel;
static char _log_output[1024];
static int _log_offset = 0;

static int _myvfprintf(FILE *stream, const char *format, va_list ap)
{
    UNUSED_PARAM(stream);
    int written;
    written = vsprintf(_log_output + _log_offset, format, ap);
    _log_offset += written;
    return written;
}

static void _normalizeLogOutput()
{
    char *start = &_log_output[0];

    // remove variable strings so we can compare deterministically in the tests
    int startlen = strlen(start);
    //printf("orig start='%s'\n", start);

    // replace final newline with terminating null
    start[startlen - 1] = '\0';

    // remove date header
    int len = startlen - 20;
    memmove(start, start + 20, len);

    // remove "ndcid=#####; " tokens
    char *starttok = start;
    while ((starttok = strstr(starttok, "ndcid=")))
    {
        // find end of id token
        char *endtok = strstr(starttok + 7, " ");
        //printf("starttok='%s'; endtok='%s'\n", starttok, endtok);
        if (!endtok)
        {
            // something's wrong, but we can't do anything about it
            assert(false);
        }

        // remove id token
        len -= (endtok - starttok + 1);
        memmove(starttok, endtok + 1, len);
        //printf("interim start='%s'\n", start);
    }

    //printf("final start='%s'\n", start);
    _log_offset -= (startlen - len);
}

static void _test_log_generator_fn(
         const char **chunk, size_t *len, jw_data_free_func *free_fn, void *arg)
{
    _log_chunk chunk_info = arg;
    _log_chunk cur = chunk_info ? chunk_info->cur : NULL;

    if (cur)
    {
        *chunk   = cur->chunk;
        *len     = cur->len;
        *free_fn = cur->free_fn;

        chunk_info->cur = cur->next;
    }
}


FCTMF_FIXTURE_SUITE_BGN(log_test)
{
    FCT_SETUP_BGN()
    {
        _initlevel = jw_log_get_level();
        jw_log_set_function(_myvfprintf);
    } FCT_SETUP_END()

    FCT_TEARDOWN_BGN()
    {
        jw_log_set_function(NULL);
        jw_log_set_level(_initlevel);
    } FCT_TEARDOWN_END()

    FCT_TEST_BGN(jw_log_message)
    {
        const char *msg;
        msg = jw_log_level_name(JW_LOG_ERROR);
        fct_chk_eq_str(msg, "ERROR");
        msg = jw_log_level_name(JW_LOG_WARN);
        fct_chk_eq_str(msg, "WARN");
        msg = jw_log_level_name(JW_LOG_INFO);
        fct_chk_eq_str(msg, "INFO");
        msg = jw_log_level_name(JW_LOG_VERBOSE);
        fct_chk_eq_str(msg, "VERBOSE");
        msg = jw_log_level_name(JW_LOG_DEBUG);
        fct_chk_eq_str(msg, "DEBUG");
        msg = jw_log_level_name(JW_LOG_TRACE);
        fct_chk_eq_str(msg, "TRACE");
        msg = jw_log_level_name(JW_LOG_MEMTRACE);
        fct_chk_eq_str(msg, "MEMTRACE");
    } FCT_TEST_END()

    FCT_TEST_BGN(jw_log)
    {
        jw_log_set_level(JW_LOG_DEBUG);

        _log_offset = 0;
        jw_log(JW_LOG_ERROR, "This is a test error");
        _normalizeLogOutput();
        fct_chk_eq_str(_log_output, "[   ERROR]: This is a test error");

        _log_offset = 0;
        jw_log(JW_LOG_WARN, "This is a test warning: %s", "with string");
        _normalizeLogOutput();
        fct_chk_eq_str(_log_output, "[    WARN]: This is a test warning: with string");

        _log_offset = 0;
        jw_log(JW_LOG_INFO, "Information: %d", 4);
        _normalizeLogOutput();
        fct_chk_eq_str(_log_output, "[    INFO]: Information: 4");

        _log_offset = 0;
        jw_log(JW_LOG_VERBOSE, "Verbose");
        _normalizeLogOutput();
        fct_chk_eq_str(_log_output, "[ VERBOSE]: Verbose");

        _log_offset = 0;
        jw_log(JW_LOG_DEBUG, "%s", "Debug");
        _normalizeLogOutput();
        fct_chk_eq_str(_log_output, "[   DEBUG]: Debug");
    } FCT_TEST_END()

    FCT_TEST_BGN(jw_log_ndc)
    {
        jw_log_set_level(JW_LOG_DEBUG);

        _log_offset = 0;
        jw_log(JW_LOG_DEBUG, "test");
        _normalizeLogOutput();
        fct_chk_eq_str(_log_output, "[   DEBUG]: test");

        int depth = jw_log_push_ndc("jid=%s", "user1@dom.com/res");
        fct_chk_eq_int(depth, 1);

        _log_offset = 0;
        jw_log(JW_LOG_DEBUG, "test");
        _normalizeLogOutput();
        fct_chk_eq_str(_log_output, "[   DEBUG]: {jid=user1@dom.com/res} test");

        jw_log_pop_ndc(depth);

        depth = jw_log_push_ndc("a");
        /* int depth2 = */ jw_log_push_ndc("b");
        int depth3 = jw_log_push_ndc("c");
        fct_chk_eq_int(depth3, 3);

        _log_offset = 0;
        jw_log(JW_LOG_DEBUG, "test");
        _normalizeLogOutput();
        fct_chk_eq_str(_log_output, "[   DEBUG]: {a} {b} {c} test");

        jw_log_pop_ndc(depth3);

        _log_offset = 0;
        jw_log(JW_LOG_DEBUG, "test");
        _normalizeLogOutput();
        fct_chk_eq_str(_log_output, "[   DEBUG]: {a} {b} test");

        // skip popping depth2 ("b")
        _log_offset = 0;
        jw_log_pop_ndc(depth);
        _normalizeLogOutput();
        fct_chk_eq_str(_log_output,
           "[    WARN]: {a} {b} ndc depth mismatch on pop (expected 2, got 1)");

        _log_offset = 0;
        jw_log(JW_LOG_DEBUG, "test");
        _normalizeLogOutput();
        fct_chk_eq_str(_log_output, "[   DEBUG]: test");

        // noop
        _log_offset = 0;
        jw_log_pop_ndc(0);
        fct_chk_eq_int(_log_offset, 0);
    } FCT_TEST_END()

    FCT_TEST_BGN(jw_log_err)
    {
        jw_err err;
        jw_log_set_level(JW_LOG_ERROR);

        _log_offset = 0;
        jw_log_err(JW_LOG_ERROR, NULL, "This is a test error");
        _normalizeLogOutput();
        fct_chk_eq_str(_log_output, "[   ERROR]: This is a test error");

        _log_offset = 0;
        JABBERWERX_ERROR(&err, JW_ERR_INVALID_ARG);
        jw_log_err(JW_LOG_ERROR, &err, "foo");
        _normalizeLogOutput();
        fct_chk_eq_str(_log_output,
                       "[   ERROR]: reason(invalid argument): foo");

        _log_offset = 0;
        jw_log_err(JW_LOG_DEBUG, &err, "foo");
        fct_chk_eq_int(_log_offset, 0);

        _log_offset = 0;
        jw_log_set_level(JW_LOG_WARN);
        JABBERWERX_ERROR(&err, JW_ERR_TIMEOUT);
        jw_log_err(JW_LOG_WARN, NULL, "This is a test warning: %s", "timeout");
        _normalizeLogOutput();
        fct_chk_eq_str(_log_output,
                       "[    WARN]: This is a test warning: timeout");

        _log_offset = 0;
        jw_log_set_level(JW_LOG_INFO);
        JABBERWERX_ERROR(&err, JW_ERR_USER);
        jw_log_err(JW_LOG_INFO,  &err, "Information: %d", 4);
        _normalizeLogOutput();
        fct_chk_eq_str(_log_output,
                       "[    INFO]: reason(user-defined error): Information: 4");

        _log_offset = 0;
        jw_log_set_level(JW_LOG_VERBOSE);
        jw_log_err(JW_LOG_VERBOSE, NULL, "Verbose");
        _normalizeLogOutput();
        fct_chk_eq_str(_log_output, "[ VERBOSE]: Verbose");

        jw_log_set_level(0);
        fct_chk(jw_log_get_level() == JW_LOG_NONE);
    } FCT_TEST_END()

    FCT_TEST_BGN(jw_log_dom)
    {
        jw_dom_ctx *ctx;
        jw_dom_node *node;
        jw_err err;

        jw_log_set_level(JW_LOG_ERROR);

        _log_offset = 0;
        jw_log_dom(JW_LOG_ERROR, NULL, "This is a NULL dom: ");
        _normalizeLogOutput();
        fct_chk_eq_str(_log_output, "[   ERROR]: This is a NULL dom: (null)");

        char dominfo[256];
        sprintf(dominfo,
                "[   ERROR]: This is a NULL dom: (context: %p, ref: %p)(null)",
                NULL, NULL);
        _log_offset = 0;
        JW_LOG_DOM_REF(JW_LOG_ERROR, NULL, "This is a NULL dom: ");
        _normalizeLogOutput();
        fct_chk_eq_str(_log_output, dominfo);

        fct_req(jw_dom_context_create(&ctx, NULL));
        fct_req(jw_dom_element_create(ctx,
                                   "{jabber:client}message",
                                    &node,
                                    &err));
        _log_offset = 0;
        jw_log_dom(JW_LOG_ERROR, node, "dom: ");
        _normalizeLogOutput();
        fct_chk_eq_str(_log_output,
                       "[   ERROR]: dom: <message xmlns='jabber:client'/>");

        sprintf(dominfo,
                "[   ERROR]: dom: (context: %p, ref: %p)<message xmlns='jabber:client'/>",
                (void *)ctx, (void *)node);
        _log_offset = 0;
        JW_LOG_DOM_REF(JW_LOG_ERROR, node, "dom: ");
        _normalizeLogOutput();
        fct_chk_eq_str(_log_output, dominfo);

        jw_dom_context_destroy(ctx);
    } FCT_TEST_END()

    FCT_TEST_BGN(jw_log_chunked)
    {
        jw_log_set_level(JW_LOG_ERROR);

        char expected[256];
        sprintf(expected, "%s", "[   ERROR]: empty");
        _log_offset = 0;
        jw_log_chunked(JW_LOG_ERROR, _test_log_generator_fn, NULL, "empty");
        _normalizeLogOutput();
        fct_chk_eq_str(_log_output, expected);

        struct _log_chunk_int chunk1 = { .chunk = "first" };
        chunk1.cur = &chunk1;
        sprintf(expected, "%s", "[   ERROR]: onefirst");
        _log_offset = 0;
        jw_log_chunked(JW_LOG_ERROR, _test_log_generator_fn, &chunk1, "one");
        _normalizeLogOutput();
        fct_chk_eq_str(_log_output, expected);

        struct _log_chunk_int chunk2 = { .chunk = "second", .len = 3 };
        chunk1.cur = &chunk1;
        chunk1.next = &chunk2;
        sprintf(expected, "%s", "[   ERROR]: twofirstsec");
        _log_offset = 0;
        jw_log_chunked(JW_LOG_ERROR, _test_log_generator_fn, &chunk1, "two");
        _normalizeLogOutput();
        fct_chk_eq_str(_log_output, expected);

        struct _log_chunk_int chunk3 =
                { .chunk = jw_data_strdup("third"), .free_fn = jw_data_free };
        chunk1.cur = &chunk1;
        chunk2.next = &chunk3;
        sprintf(expected, "%s", "[   ERROR]: threefirstsecthird");
        _log_offset = 0;
        jw_log_chunked(JW_LOG_ERROR, _test_log_generator_fn, &chunk1, "three");
        _normalizeLogOutput();
        fct_chk_eq_str(_log_output, expected);
    } FCT_TEST_END()

    FCT_TEST_BGN(jw_log_set_level)
    {
        jw_log_set_level(JW_LOG_ERROR);
        _log_offset = 0;
        jw_log(JW_LOG_MEMTRACE, "MemTrace");
        fct_chk_eq_int(_log_offset, 0);
        _log_offset = 0;
        jw_log(JW_LOG_TRACE, "Trace");
        fct_chk_eq_int(_log_offset, 0);
        _log_offset = 0;
        jw_log(JW_LOG_DEBUG, "Debug");
        fct_chk_eq_int(_log_offset, 0);
        _log_offset = 0;
        jw_log(JW_LOG_DEBUG, "Verbose");
        fct_chk_eq_int(_log_offset, 0);
        _log_offset = 0;
        jw_log(JW_LOG_DEBUG, "Information");
        fct_chk_eq_int(_log_offset, 0);
        _log_offset = 0;
        jw_log(JW_LOG_DEBUG, "Warn");
        fct_chk_eq_int(_log_offset, 0);
        _log_offset = 0;
        jw_log(JW_LOG_ERROR, "Error");
        fct_chk_neq_int(_log_offset, 0);

        jw_log_set_level(JW_LOG_NONE);
        _log_offset = 0;
        jw_log(JW_LOG_ERROR, "Error");
        fct_chk_eq_int(_log_offset, 0);
    } FCT_TEST_END()
} FCTMF_FIXTURE_SUITE_END()
