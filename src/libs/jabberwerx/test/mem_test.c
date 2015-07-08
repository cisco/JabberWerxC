/**
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

#include <expat.h>
#include <event2/buffer.h>
#include <curl/curl.h>
#include <jabberwerx/jid.h>
#include <jabberwerx/util/serializer.h>
#include <jabberwerx/util/str.h>
#include <jabberwerx/util/parser.h>
#include <jabberwerx/util/base64.h>
#include <jabberwerx/crypto/sha1.h>
#include "fct.h"
#include "test_utils.h"

// uses "private" type defs from source. NOT for use outside unit tests
#include "../src/include/pool_types.h"

// get access to the variables declared in mem.c
extern jw_data_malloc_func _malloc_func;
extern jw_data_realloc_func _realloc_func;
extern jw_data_free_func _free_func;

// cached external refs
static jw_data_malloc_func mallocFnOrig   = NULL;
static jw_data_realloc_func reallocFnOrig = NULL;
static jw_data_free_func freeFnOrig       = NULL;

static oom_test_data _oom_test = {
                        .jwcAllocCount = 0,
                        .jwcAllocLimit = -1,
                        .failureAttempts = 0,
                        .numMallocCalls = 0,
                        .numReallocCalls = 0,
                        .numFreeCalls = 0
                    };

static void *mallocFn (size_t size)
{
    void *ret = NULL;

    ++_oom_test.numMallocCalls;
    if (_oom_test.jwcAllocLimit < 0 ||
        _oom_test.jwcAllocCount < _oom_test.jwcAllocLimit)
    {
        ret = mallocFnOrig(size);
    }
    ++_oom_test.jwcAllocCount;
    return ret;
}

static void * reallocFn (void * ptr, size_t size)
{
    void *ret = NULL;

    if (NULL == ptr)
    {   //numReallocCalls counts the number of references that should be freed,
        //non NULL realloc pointers are already accounted for in their initial
        //allocation.
        ++_oom_test.numReallocCalls;
    }

    if (_oom_test.jwcAllocLimit < 0 ||
        _oom_test.jwcAllocCount < _oom_test.jwcAllocLimit)
    {
        ret = reallocFnOrig(ptr, size);
    }
    ++_oom_test.jwcAllocCount;
    return ret;
}

static void freeFn (void * ptr)
{
    ++_oom_test.numFreeCalls;
    freeFnOrig(ptr);
}

void oom_set_enabled(bool on)
{
    _oom_test.jwcAllocCount = _oom_test.numMallocCalls = 0;
    _oom_test.numReallocCalls = _oom_test.numFreeCalls = 0;
    _oom_test.jwcAllocLimit = -1;

    if (mallocFnOrig && !on)
    {
        jw_data_set_memory_funcs(mallocFnOrig, reallocFnOrig, freeFnOrig);
        mallocFnOrig  = NULL;
        reallocFnOrig = NULL;
        freeFnOrig    = NULL;
    }
    else if (!mallocFnOrig && on)
    {
        mallocFnOrig  = _malloc_func;
        reallocFnOrig = _realloc_func;
        freeFnOrig    = _free_func;
        jw_data_set_memory_funcs(mallocFn, reallocFn, freeFn);
    }
}

oom_test_data *oom_get_data()
{
    return &_oom_test;
}

int page_count(jw_pool *pool)
{
    int ret = 0;
    _pool_page page = pool->pages;

    while(page)
    {
        ret++;
        page = page->next;
    }
    return ret;
}

int cleaner_count(jw_pool *pool)
{
    int ret = 0;
    _pool_cleaner_ctx cleaner = pool->cleaners;

    while(cleaner)
    {
        ret++;
        cleaner = cleaner->next;
    }
    return ret;
}

_pool_page get_page(jw_pool *pool, int idx)
{
    _pool_page ret = pool->pages;
    int i;

    for (i = 0; (i < idx) && ret; ++i)
    {
        ret = ret->next;
    }
    return ret;
}

_pool_cleaner_ctx get_cleaner(jw_pool *pool, int idx)
{
    _pool_cleaner_ctx ret = pool->cleaners;
    int i;

    for (i = 0; (i < idx) && ret; ++i)
    {
        ret = ret->next;
    }
    return ret;
}

bool cleaner_hit = false;
void* expected = NULL;
void test_cleaner(void* ptr)
{
    cleaner_hit = (expected == ptr);
}


static jw_dom_ctx   *g_ctx;
static jw_dom_node *_create_simple_node()
{
    jw_dom_node     *elem;

    jw_dom_context_create(&g_ctx, NULL);
    jw_dom_element_create(g_ctx, "{jabber:client}presence", &elem, NULL);
    return elem;
}

static void mock_evt1_callback1(jw_event_data evt, void *arg)
{
    UNUSED_PARAM(evt);
    UNUSED_PARAM(arg);

    return;
}


FCTMF_SUITE_BGN(mem_test)
{
    FCT_TEST_BGN(jw_data_calloc)
    {
        void* ptr = jw_data_calloc(1, 4);
        fct_req(ptr);
        fct_chk_eq_int(0, memcmp("\0\0\0\0", ptr, 4));
        jw_data_free(ptr);
    } FCT_TEST_END()

    FCT_TEST_BGN(jw_data_strdup)
    {
        char*  dup;
        const char* src = "hi-de-ho";

        dup = jw_data_strdup(src);
        fct_chk(dup != NULL);
        fct_chk_eq_str(src, dup);
        jw_data_free(dup);

        dup = jw_data_strdup("");
        fct_chk(dup != NULL);
        fct_chk_eq_str("", dup);
        jw_data_free(dup);

        dup = jw_data_strdup(NULL);
        fct_chk(dup == NULL);

        OOM_RECORD_ALLOCS(dup = jw_data_strdup(src))
        jw_data_free(dup);
        OOM_TEST_INIT()
        //no jw_err checking
        OOM_TEST(NULL, jw_data_strdup(src))
    } FCT_TEST_END()

    FCT_TEST_BGN(jw_data_strndup)
    {
        char*  dup;
        const char* src = "hi-de-ho";

        dup = jw_data_strndup(src, jw_strlen(src));
        fct_chk(dup != NULL);
        fct_chk_eq_str(src, dup);
        jw_data_free(dup);

        dup = jw_data_strndup(src, 100);
        fct_chk(dup != NULL);
        fct_chk_eq_str(src, dup);
        jw_data_free(dup);

        dup = jw_data_strndup(src, 3);
        fct_chk(dup != NULL);
        fct_chk_eq_str("hi-", dup);
        jw_data_free(dup);

        dup = jw_data_strndup("", 0);
        fct_chk(dup != NULL);
        fct_chk_eq_str("", dup);
        jw_data_free(dup);

        dup = jw_data_strndup(NULL, 0);
        fct_chk(dup == NULL);


        OOM_RECORD_ALLOCS(dup = jw_data_strndup(src, 5))
        jw_data_free(dup);
        OOM_TEST_INIT()
        //no jw_err checking
        OOM_TEST(NULL, jw_data_strndup(src, 5))
    } FCT_TEST_END()

#ifndef DISABLE_POOL_PAGES
    FCT_TEST_BGN(jw_pool_create_destroy)
    {
        jw_err err;
        jw_pool *pool;
        _pool_page page;
        _pool_cleaner_ctx cleaner;
        /* create with pages */
        fct_chk(jw_pool_create(1024, &pool, &err));
        fct_chk(pool);
        fct_chk(pool->size == 1024);
        fct_chk(pool->page_size == 1024);

        /* should be 1 page */
        fct_chk_eq_int(1, page_count(pool));
        page = get_page(pool, 0);
        fct_chk(page->size == 1024);
        fct_chk(page->used == 0);

        /* should be one cleaner (for the page) */
        fct_chk_eq_int(1, cleaner_count(pool));
        /* cleaner should be for page */
        cleaner = get_cleaner(pool, 0);
        fct_chk(cleaner->arg == page);
        jw_pool_destroy(pool);

        /* without pages */
        fct_chk(jw_pool_create(0, &pool, &err));
        fct_chk(pool);
        fct_chk_eq_int(0, pool->size);
        fct_chk_eq_int(0, pool->page_size);
        /* should be 0 pages */
        fct_chk_eq_int(0, page_count(pool));
        /* should be 0 cleaners */
        fct_chk_eq_int(0, cleaner_count(pool));
        jw_pool_destroy(pool);

    } FCT_TEST_END()

    FCT_TEST_BGN(jw_pool_malloc)
    {
        jw_pool *pool;
        jw_err err;
        void *ptr;
        size_t i;

        _pool_page page;
        _pool_cleaner_ctx cleaner;

        fct_chk(jw_pool_create(1024, &pool, &err));
        fct_chk(jw_pool_malloc(pool, 512, &ptr, &err));
        fct_chk(ptr != NULL);
        memset(ptr, 1, 512);
        fct_chk(jw_pool_malloc(pool, 615, &ptr, &err));
        fct_chk(ptr != NULL);

        fct_chk(pool->size == 2048);
        fct_chk(pool->page_size == 1024);

        fct_chk_eq_int(2, page_count(pool));

        page = get_page(pool, 0);
        fct_chk(page);
        fct_chk(page->size == 1024);
        fct_chk_eq_int(page->used, 615);

        page = get_page(pool, 1);
        fct_chk(page->size == 1024);
        fct_chk_eq_int(page->used, 512);

        fct_chk_eq_int(2, cleaner_count(pool));

        cleaner = get_cleaner(pool, 0);
        page = get_page(pool, 0);
        fct_chk(cleaner->arg == page);

        cleaner = get_cleaner(pool, 1);
        page = get_page(pool, 1);
        fct_chk(cleaner->arg == page);

        jw_pool_destroy(pool);

        fct_req(jw_pool_create(1024, &pool, &err));
        /* test a number of small allocations, enough to fill a page, insure mallocs are word aligned*/
        fct_chk(jw_pool_malloc(pool, 1, &ptr, &err));
        for (i = 1; i < 115; ++i)
        {
            size_t  sz = (i % (sizeof(uintptr_t) * 2)) + 1;
            fct_chk(jw_pool_malloc(pool, sz, &ptr, &err));
        }
        jw_pool_destroy(pool);
    } FCT_TEST_END()

    FCT_TEST_BGN(jw_pool_malloc_overallocate)
    {
        jw_pool *pool;
        jw_err err;
        void* ptr;
        _pool_page page1;
        _pool_cleaner_ctx cleaner;

        fct_chk(jw_pool_create(1024, &pool, &err));
        fct_chk(jw_pool_malloc(pool, 512, &ptr, &err));
        fct_chk(ptr != NULL);

        fct_chk(jw_pool_malloc(pool, 2048, &ptr, &err));
        fct_chk(ptr != NULL);

        fct_chk(pool->size == 3072);
        fct_chk(pool->page_size == 1024);

        fct_chk_eq_int(1, page_count(pool));

        page1 = get_page(pool, 0);
        fct_chk(page1);
        fct_chk(page1->size == 1024);
        fct_chk_eq_int(page1->used, 512);

        fct_chk_eq_int(2, cleaner_count(pool));

        cleaner = get_cleaner(pool, 0);
        page1 = get_page(pool, 0);
        fct_chk(cleaner->arg == ptr);

        cleaner = get_cleaner(pool, 1);
        fct_chk(cleaner->arg == page1);

        jw_pool_destroy(pool);

    } FCT_TEST_END()

    FCT_TEST_BGN(jw_pool_strdup_shorterpool)
    {
        jw_pool *pool;
        jw_err err;
        char*  dup;
        _pool_page page;
        const char* src;

        src="\x2d\xa7\x5d\xa5\xc8\x54\x78\xdf\x42\xdf\x0f\x91\x77\x00\x24\x1e\xd2\x82\xf5\x99\x2d\xa7\x5d\xa5\xc8\x54\x78\xdf\x42\xdf\x0f\x91\x77\x00\x24\x1e\xd2\x82\xf5\x99";
        fct_chk(jw_pool_create(8, &pool, &err));
        fct_chk(jw_pool_strdup(pool, src, &dup, &err));
        fct_chk(dup != NULL);
        fct_chk_eq_str(src, dup);

        fct_chk_eq_int(pool->size, 22);
        fct_chk_eq_int(pool->page_size, 8);
        fct_chk_eq_int(1, page_count(pool));
        page = get_page(pool, 0);
        fct_chk(page);
        fct_chk_eq_int(page->used, 0);

        jw_pool_destroy(pool);
    } FCT_TEST_END()

#endif
    FCT_TEST_BGN(jw_pool_calloc)
    {
        jw_pool *pool;
        jw_err err;
        void* ptr;

        fct_chk(jw_pool_create(1024, &pool, &err));
        fct_chk(jw_pool_calloc(pool, 4, 128, &ptr, &err));
        fct_chk(ptr != NULL);

        jw_pool_destroy(pool);
    } FCT_TEST_END()

    FCT_TEST_BGN(jw_pool_calloc_nobytes)
    {
        jw_pool *pool;
        jw_err err;
        void* ptr;

        fct_chk(jw_pool_create(1024, &pool, &err));
        fct_chk(jw_pool_calloc(pool, 4, 0, &ptr, &err));
        fct_chk(ptr == NULL);

        jw_pool_destroy(pool);
    } FCT_TEST_END()

    FCT_TEST_BGN(jw_pool_strdup)
    {
        jw_pool *pool;
        jw_err err;
        char*  dup;
        const char* src = "hi-de-ho";

        fct_chk(jw_pool_create(1024, &pool, &err));
        fct_chk(jw_pool_strdup(pool, src, &dup, &err));
        fct_chk(dup != NULL);
        fct_chk_eq_str(src, dup);

        fct_chk(jw_pool_strdup(pool, "", &dup, &err));
        fct_chk(dup != NULL);
        fct_chk_eq_str("", dup);

        fct_chk(jw_pool_strdup(pool, NULL, &dup, &err));
        fct_chk(dup == NULL);

        jw_pool_destroy(pool);
    } FCT_TEST_END()

    FCT_TEST_BGN(jw_pool_add_cleaner)
    {
        jw_pool *pool;
        jw_err err;
        void* ptr;

        fct_chk(jw_pool_create(1024, &pool, &err));

        fct_chk(jw_pool_malloc(pool, 512, &ptr, &err));
        fct_chk(jw_pool_add_cleaner(pool, &test_cleaner, ptr, &err));
        expected = ptr;
        jw_pool_destroy(pool);
        fct_chk(cleaner_hit);
        cleaner_hit = false;
        expected = NULL;
    } FCT_TEST_END()

    FCT_TEST_BGN(jw_pool_add_cleaner_nonpool)
    {
        jw_pool *pool;
        jw_err err;
        void* ptr;

        fct_chk(jw_pool_create(512, &pool, &err));

        ptr = (void *)malloc(512);
        fct_chk(ptr != NULL);

        fct_chk(jw_pool_add_cleaner(pool, &test_cleaner, ptr, &err));
        expected = ptr;
        jw_pool_destroy(pool);
        fct_chk(cleaner_hit);
        cleaner_hit = true;
        expected = NULL;
        free(ptr);
    } FCT_TEST_END()

    FCT_TEST_BGN(jw_data_memory)
    {
        void *dummy;
        oom_test_data *tdata = oom_get_data();
        oom_set_enabled(true);

        dummy = jw_data_malloc(10);
        fct_chk_eq_int(tdata->numMallocCalls, 1);

        dummy = jw_data_realloc(dummy, 5);
        fct_chk_eq_int(tdata->numReallocCalls, 0);
        jw_data_free(dummy);
        fct_chk_eq_int(tdata->numFreeCalls, 1);

        dummy = jw_data_realloc(NULL, 5);
        fct_chk_eq_int(tdata->numReallocCalls, 1);
        jw_data_free(dummy);
        fct_chk_eq_int(tdata->numFreeCalls, 2);

        // NULL should be no-op
        jw_data_free(NULL);
        fct_chk_eq_int(tdata->numFreeCalls, 2);

        // Reset memory functions
        jw_data_set_memory_funcs(NULL, NULL, NULL);

        dummy = jw_data_malloc(10);
        fct_chk_eq_int(tdata->numMallocCalls, 1);

        dummy = jw_data_realloc(dummy, 5);
        fct_chk_eq_int(tdata->numReallocCalls, 1);

        jw_data_free(dummy);
        fct_chk_eq_int(tdata->numFreeCalls, 2);
        oom_set_enabled(false);
    } FCT_TEST_END()

    FCT_TEST_BGN(jw_memory_3rdparty)
    {
        // ensure 3rd party libs are calling us for their mem allocation needs
        oom_test_data *tdata = oom_get_data();

        // libevent
        /*
        oom_set_enabled(true);
        struct evbuffer * buf = evbuffer_new();
        evbuffer_free(buf);
        fct_chk_eq_int(tdata->numMallocCalls, tdata->numFreeCalls);
        fct_chk_neq_int(0, tdata->numMallocCalls);
        */

        // expat
        oom_set_enabled(true);
        XML_Memory_Handling_Suite xmlMs = {
            .malloc_fcn  = jw_data_malloc,
            .realloc_fcn = jw_data_realloc,
            .free_fcn    = jw_data_free
        };
        const char NS_DELIM = '#';
        XML_Parser parser = XML_ParserCreate_MM(NULL, &xmlMs, &NS_DELIM);
        XML_ParserFree(parser);
        fct_chk_eq_int(tdata->numMallocCalls, tdata->numFreeCalls);
        fct_chk_neq_int(0, tdata->numMallocCalls);

        // curl
        /*
        oom_set_enabled(true);
        CURL *easy = curl_easy_init();
        curl_easy_cleanup(easy);
        fct_chk_eq_int(tdata->numMallocCalls, tdata->numFreeCalls);
        fct_chk_neq_int(0, tdata->numMallocCalls);
        */

        oom_set_enabled(false);
    } FCT_TEST_END()

    FCT_TEST_BGN(jw_sha1_create_no_mem)
    {
        jw_sha1_ctx *ctx;

        OOM_SIMPLE_TEST(jw_sha1_create(&ctx, &err))
        jw_sha1_destroy(ctx);
    } FCT_TEST_END()

    FCT_TEST_BGN(jw_sha1_compute_no_mem)
    {
        uint8_t *digest;
        uint8_t *input;
        size_t digest_len;
        input = (uint8_t*)"\0username\0password";
        digest = NULL;
        OOM_SIMPLE_TEST(jw_sha1(input, 18, &digest, &digest_len, &err))
        jw_data_free(digest);
    } FCT_TEST_END()

    FCT_TEST_BGN(jw_sha1_result_no_mem)
    {
        jw_err err;
        jw_sha1_ctx *ctx;
        uint8_t *digest;
        uint8_t *input;
        size_t digest_len;

        input = (uint8_t*)"\0username\0password";
        jw_sha1_create(&ctx, &err);
        fct_chk(jw_sha1_input(ctx, input, 0, &err) == true);
        //OOM errors from openssl get translated to other error types,
        //skip err code tests
        digest = NULL;
        OOM_SIMPLE_TEST_NO_CHECK(jw_sha1_result(ctx, &digest, &digest_len, &err));
        jw_data_free(digest);
        jw_sha1_destroy(ctx);
    } FCT_TEST_END()

    /* htable_tests */
    FCT_TEST_BGN(jw_htable_no_mem)
    {
        jw_htable   *table;
        OOM_SIMPLE_TEST(jw_htable_create(7,
                                 jw_int_hashcode,
                                 jw_int_compare,
                                 &table,
                                 &err));
        jw_htable_destroy(table);
    } FCT_TEST_END()
    FCT_TEST_BGN(jw_htable_put_no_mem)
    {
        jw_htable   *table;
        jw_err      err;
        fct_req(jw_htable_create(7,
                                 jw_int_hashcode,
                                 jw_int_compare,
                                 &table,
                                 NULL));
        OOM_RECORD_ALLOCS(jw_htable_put(table, "key1", "value one", NULL, &err))
        OOM_TEST_INIT()
            jw_htable_remove(table, "key1");
        OOM_TEST(&err, jw_htable_put(table, "key1", "value one", NULL, &err))
        jw_htable_destroy(table);
    } FCT_TEST_END()

    /* base64_tests */
    FCT_TEST_BGN(jw_base64_encode_no_mem)
    {
        char   *result;
        size_t  result_len;
        OOM_SIMPLE_TEST(jw_base64_encode((const uint8_t*)"1",
                                         1,
                                         &result,
                                         &result_len,
                                         &err));
        jw_data_free(result);
    } FCT_TEST_END()

    FCT_TEST_BGN(jw_base64_decode_no_mem)
    {
        uint8_t *result;
        size_t   result_len;
        OOM_SIMPLE_TEST(jw_base64_decode("MQ==", 4, &result, &result_len, &err));
        jw_data_free(result);
    } FCT_TEST_END()
     /* jid_tests */
    FCT_TEST_BGN(jw_jid_ctx_create_no_mem)
    {
        jw_jid_ctx *ctx;

        OOM_SIMPLE_TEST(jw_jid_context_create(5, &ctx, &err));
        jw_jid_context_destroy(ctx);

    } FCT_TEST_END()

    FCT_TEST_BGN(jw_jid_localpart_no_mem)
    {
        char *buff;
        size_t buff_len;

        OOM_SIMPLE_TEST(jw_jid_escape_localpart("fo@o", &buff, &buff_len, &err));
        jw_data_free(buff);
        OOM_SIMPLE_TEST(jw_jid_unescape_localpart("fo\\40o", &buff, &buff_len, &err));
        jw_data_free(buff);

    } FCT_TEST_END()

    FCT_TEST_BGN(jw_jid_create_by_parts_no_mem)
    {
        jw_jid_ctx *ctx;
        jw_jid *jid;
        jw_err err;

        fct_req(jw_jid_context_create(0, &ctx, NULL));
        OOM_RECORD_ALLOCS(jw_jid_create_by_parts(ctx, "foo", "bar", "baz", &jid, &err))
        // TODO: fix segfault on > 1 alloction failures in jw_jid_create_by_parts
        //       and remove this line.
        oom_get_data()->failureAttempts = 1;
        OOM_TEST_INIT()
            jw_jid_context_destroy(ctx);
            fct_req(jw_jid_context_create(0, &ctx, NULL));
        OOM_TEST(&err, jw_jid_create_by_parts(ctx, "foo", "bar", "baz", &jid, &err))
        jw_jid_context_destroy(ctx);

    } FCT_TEST_END()

    FCT_TEST_BGN(jw_jid_create_no_mem)
    {
        jw_jid_ctx *ctx;
        jw_jid *jid;
        jw_err err;

        fct_req(jw_jid_context_create(0, &ctx, NULL));
        OOM_RECORD_ALLOCS(jw_jid_create(ctx, "foo@bar/baz", &jid, &err))
        // TODO: fix segfault on > 1 alloction failures in jw_jid_create
        //       and remove this line.
        oom_get_data()->failureAttempts = 1;
        OOM_TEST_INIT()
            jw_jid_context_destroy(ctx);
            fct_req(jw_jid_context_create(0, &ctx, NULL));
        OOM_TEST(&err, jw_jid_create(ctx, "foo@bar/baz", &jid, &err))
        jw_jid_context_destroy(ctx);

    } FCT_TEST_END()

    FCT_TEST_BGN(jw_jid_import_no_mem)
    {
        jw_jid_ctx *ctx, *ictx;
        jw_jid *jid, *ijid;
        jw_err  err;

        fct_req(jw_jid_context_create(0, &ctx, NULL));
        fct_req(jw_jid_context_create(0, &ictx, NULL));
        fct_chk(jw_jid_create(ctx, "foo@bar/baz", &jid, NULL));
        OOM_RECORD_ALLOCS(jw_jid_import(ictx, jid, &ijid, &err))
        // TODO: fix segfault on > 1 alloction failures in jw_jid_import
        //       and remove this line.
        oom_get_data()->failureAttempts = 1;
        OOM_TEST_INIT()
            jw_jid_context_destroy(ctx);
            jw_jid_context_destroy(ictx);
            fct_req(jw_jid_context_create(0, &ctx, NULL));
            fct_req(jw_jid_context_create(0, &ictx, NULL));
            fct_chk(jw_jid_create(ctx, "foo@bar/baz", &jid, NULL));
        OOM_TEST(&err, jw_jid_import(ictx, jid, &ijid, &err))
        jw_jid_context_destroy(ctx);
        jw_jid_context_destroy(ictx);

    } FCT_TEST_END()

           /* dom_tests*/
    FCT_TEST_BGN(jw_dom_ctx_create_no_mem)
    {
        jw_dom_ctx      *ctx;

        OOM_SIMPLE_TEST(jw_dom_context_create(&ctx, &err));
        jw_dom_context_destroy(ctx);

    } FCT_TEST_END()
    FCT_TEST_BGN(jw_dom_elem_create_no_mem)
    {
        jw_dom_node     *elem;
        jw_dom_ctx *ctx;
        jw_err err;
        OOM_POOL_TEST_BGN
            fct_req(jw_dom_context_create(&ctx, NULL) == true);
            OOM_RECORD_ALLOCS(jw_dom_element_create(ctx,
                                           "{jabber:client}presence",
                                           &elem,
                                           &err))
            OOM_TEST_INIT()
                jw_dom_context_destroy(ctx);
                fct_req(jw_dom_context_create(&ctx, NULL) == true);
            OOM_TEST(&err,
                     jw_dom_element_create(ctx,
                                           "{jabber:client}presence",
                                           &elem,
                                           &err))
            jw_dom_context_destroy(ctx);
        OOM_POOL_TEST_END
    } FCT_TEST_END()

    FCT_TEST_BGN(jw_dom_set_attribute_no_mem)
    {
        jw_dom_node     *elem;
        jw_err          err;
        jw_dom_ctx *ctx;
        OOM_POOL_TEST_BGN
            fct_req(jw_dom_context_create(&ctx, &err) == true);
            fct_req(jw_dom_element_create(ctx, "{jabber:client}presence",
                                          &elem, &err) == true);
            OOM_RECORD_ALLOCS(jw_dom_set_attribute(elem,
                                     "{http://www.w3.org/XML/1998/namespace}lang",
                                     "en",
                                     &err))
            OOM_TEST_INIT()
                jw_dom_context_destroy(ctx);
                fct_req(jw_dom_context_create(&ctx, &err) == true);
                fct_req(jw_dom_element_create(ctx, "{jabber:client}presence",
                                              &elem, &err) == true);
            OOM_TEST(&err,
                     jw_dom_set_attribute(elem,
                                     "{http://www.w3.org/XML/1998/namespace}lang",
                                     "en",
                                     &err))
            jw_dom_context_destroy(ctx);
        OOM_POOL_TEST_END
    } FCT_TEST_END()

    FCT_TEST_BGN(jw_dom_text_create_no_mem)
    {
        jw_dom_node *elem;
        jw_dom_ctx  *ctx;

        OOM_POOL_TEST_BGN
            fct_req(jw_dom_context_create(&ctx, NULL) == true);
            fct_req(jw_dom_element_create(ctx,
                                          "{jabber:client}body",
                                          &elem,
                                          NULL) == true);
            // This will succeed because the memory has already been allocated.
    #ifndef DISABLE_POOL_PAGES //unless pool allocations are turned off
            jw_dom_node *child;
            OOM_SIMPLE_TEST(jw_dom_text_create(ctx,
                                               "wherefore art thou, Romeo!",
                                                &child,
                                                &err))
    #endif
            jw_dom_context_destroy(ctx);
        OOM_POOL_TEST_END
    } FCT_TEST_END()

    FCT_TEST_BGN(jw_dom_element_namespace_no_mem)
    {
        jw_dom_ctx *ctx;
        jw_dom_node *elem;
        jw_err  err;

        fct_req(jw_dom_context_create(&ctx, NULL) == true);
        fct_req(jw_dom_element_create(ctx,
                                      "{http://etherx.jabber.org/streams}stream",
                                      &elem,
                                      NULL) == true);
        OOM_RECORD_ALLOCS(jw_dom_put_namespace(elem, "", "jabber:client", &err))
        OOM_TEST_INIT()
            jw_dom_context_destroy(ctx);
            fct_req(jw_dom_context_create(&ctx, NULL) == true);
            fct_req(jw_dom_element_create(ctx,
                                          "{http://etherx.jabber.org/streams}stream",
                                          &elem,
                                          NULL) == true);
        OOM_TEST(&err, jw_dom_put_namespace(elem, "", "jabber:client", &err))
        jw_dom_context_destroy(ctx);

        /* TODO: Figure why this check is failing */
        /*fct_chk(jw_dom_put_namespace(elem,
                                     "stream",
                                     "http://etherx.jabber.org/streams",
                                     &err) == false); */
    } FCT_TEST_END()
    FCT_TEST_BGN(jw_dom_import_no_mem)
    {
        jw_dom_ctx      *dupCtx;
        jw_dom_node     *orig, *cpy;
        jw_err          err;
        {
            jw_dom_node *child, *gchild;
            fct_req(jw_dom_context_create(&g_ctx, &err) == true);
            fct_req(jw_dom_element_create(g_ctx,
                                          "{jabber:client}message",
                                          &orig,
                                          &err) == true);
            fct_req(jw_dom_put_namespace(orig,
                                         "",
                                         "jabber:client",
                                         &err) == true);
            fct_req(jw_dom_set_attribute(orig,
                                         "{}from",
                                         "juliet@capulet.net/balcony",
                                         &err) == true);
            fct_req(jw_dom_set_attribute(orig,
                                         "{}id",
                                         "some-random-message-id",
                                         &err) == true);
            fct_req(jw_dom_set_attribute(orig,
                                         "{}to",
                                         "romeo@montegue.net",
                                         &err) == true);
            fct_req(jw_dom_set_attribute(orig,
                                         "{}type",
                                         "chat",
                                         &err) == true);

            fct_req(jw_dom_element_create(g_ctx,
                                          "{jabber:client}thread",
                                          &child,
                                          &err) == true);
            fct_req(jw_dom_add_child(orig, child, &err) == true);
            fct_req(jw_dom_text_create(g_ctx,
                                       "some-random-guid",
                                       &gchild,
                                       &err) == true);
            fct_req(jw_dom_add_child(child, gchild, &err) == true);

            fct_req(jw_dom_element_create(g_ctx,
                                          "{jabber:client}body",
                                          &child,
                                          &err) == true);
            fct_req(jw_dom_add_child(orig, child, &err) == true);
            fct_req(jw_dom_text_create(g_ctx,
                                       "wherefore art thou, romeo!",
                                       &gchild,
                                       &err) == true);
            fct_req(jw_dom_add_child(child, gchild, &err) == true);


            fct_req(jw_dom_element_create(g_ctx,
                                          "{http://jabber.org/protocol/chatstates}active",
                                          &child,
                                          &err) == true);
            fct_req(jw_dom_put_namespace(child,
                                         "",
                                         "http://jabber.org/protocol/chatstates",
                                         &err) == true);
            fct_req(jw_dom_add_child(orig, child, &err) == true);

            fct_req(jw_dom_element_create(g_ctx,
                                          "{http://jabber.org/protocol/xhtml-im}html",
                                          &child,
                                          &err) == true);
            fct_req(jw_dom_put_namespace(child,
                                         "",
                                         "http://jabber.org/protocol/xhtml-im",
                                         &err) == true);
            fct_req(jw_dom_add_child(orig, child, &err) == true);
        }

        //run through import tests twice, with and without pool paging, to cover
        //bith paths through jw_pool allocations. This is a good test for
        //coverage as import must allocate "large" numbers of small blocks.
        OOM_POOL_TEST_BGN
            /* check out of memory error */
            fct_req(jw_dom_context_create(&dupCtx, &err) == true);
            OOM_RECORD_ALLOCS(jw_dom_import(dupCtx, orig, false, &cpy, &err))
            OOM_TEST_INIT()
                jw_dom_context_destroy(dupCtx);
                fct_req(jw_dom_context_create(&dupCtx, &err) == true);
            OOM_TEST(&err, jw_dom_import(dupCtx, orig, false, &cpy, &err))
            jw_dom_context_destroy(dupCtx);

            fct_req(jw_dom_context_create(&dupCtx, &err) == true);
            OOM_RECORD_ALLOCS(jw_dom_import(dupCtx, orig, true, &cpy, &err))
            OOM_TEST_INIT()
                jw_dom_context_destroy(dupCtx);
                fct_req(jw_dom_context_create(&dupCtx, &err) == true);
            OOM_TEST(&err, jw_dom_import(dupCtx, orig, true, &cpy, &err))
            jw_dom_context_destroy(dupCtx);
        OOM_POOL_TEST_END

    } FCT_TEST_END()
    FCT_TEST_BGN(jw_dom_clone_no_mem)
    {
        jw_dom_node     *orig, *dup;
        jw_err          err;

        {
            jw_dom_node *child, *gchild;
            fct_req(jw_dom_element_create(g_ctx,
                                          "{jabber:client}message",
                                          &orig,
                                          &err) == true);
            fct_req(jw_dom_put_namespace(orig,
                                         "",
                                         "jabber:client",
                                         &err) == true);
            fct_req(jw_dom_set_attribute(orig,
                                         "{}from",
                                         "juliet@capulet.net/balcony",
                                         &err) == true);
            fct_req(jw_dom_set_attribute(orig,
                                         "{}to",
                                         "romeo@montegue.net",
                                         &err) == true);
            fct_req(jw_dom_element_create(g_ctx,
                                          "{jabber:client}thread",
                                          &child,
                                          &err) == true);
            fct_req(jw_dom_add_child(orig, child, &err) == true);

            fct_req(jw_dom_element_create(g_ctx,
                                          "{jabber:client}body",
                                          &child,
                                          &err) == true);
            fct_req(jw_dom_add_child(orig, child, &err) == true);
            fct_req(jw_dom_text_create(g_ctx,
                                       "wherefore art thou, romeo!",
                                       &gchild,
                                       &err) == true);
            fct_req(jw_dom_add_child(child, gchild, &err) == true);

            fct_req(jw_dom_element_create(g_ctx,
                                          "{http://jabber.org/protocol/chatstates}active",
                                          &child,
                                          &err) == true);
            fct_req(jw_dom_put_namespace(child,
                                         "",
                                         "http://jabber.org/protocol/chatstates",
                                         &err) == true);
            fct_req(jw_dom_add_child(orig, child, &err) == true);

            fct_req(jw_dom_element_create(g_ctx,
                                          "{http://jabber.org/protocol/xhtml-im}html",
                                          &child,
                                          &err) == true);
            fct_req(jw_dom_put_namespace(child,
                                         "",
                                         "http://jabber.org/protocol/xhtml-im",
                                         &err) == true);
            fct_req(jw_dom_add_child(orig, child, &err) == true);
            fct_req(jw_dom_element_create(g_ctx,
                                          "{http://www.w3.org/1999/xhtml}body",
                                          &gchild,
                                          &err) == true);
            fct_req(jw_dom_put_namespace(gchild,
                                         "",
                                         "http://www.w3.org/1999/xhtml",
                                         &err) == true);
            fct_req(jw_dom_add_child(child, gchild, &err) == true);

            child = gchild;
            fct_req(jw_dom_element_create(g_ctx,
                                          "{http://www.w3.org/1999/xhtml}p",
                                          &gchild,
                                          &err) == true);
            fct_req(jw_dom_add_child(child, gchild, &err) == true);
        }
        OOM_POOL_TEST_BGN
            OOM_SIMPLE_TEST(jw_dom_clone(orig, true, &dup, &err));
        OOM_POOL_TEST_END
        jw_dom_context_destroy(g_ctx); //???

    } FCT_TEST_END()
    /* serializer_tests*/
    FCT_TEST_BGN(jw_serialize_xml_no_mem)
    {
        jw_dom_node     *root;
        char            *xmlAct = NULL;
        size_t          len;
        OOM_POOL_TEST_BGN
            root = _create_simple_node();
            OOM_SIMPLE_TEST(jw_serialize_xml(root, &xmlAct, &len, &err));
            jw_data_free(xmlAct);
            jw_dom_context_destroy(jw_dom_get_context(root));
        OOM_POOL_TEST_END
    } FCT_TEST_END()
    FCT_TEST_BGN(jw_serializer_create_no_mem)
    {
        jw_serializer   *ser = NULL;
        struct evbuffer *output;

        fct_req(output = evbuffer_new());
        OOM_SIMPLE_TEST(jw_serializer_create(output, &ser, &err));
        jw_serializer_destroy(ser);
        evbuffer_free(output);
    } FCT_TEST_END()
    FCT_TEST_BGN(jw_serializer_write_start_no_mem)
    {
        jw_dom_node     *root;
        jw_err          err;
        struct evbuffer *output;
        jw_serializer   *ser;

        root = _create_simple_node();
        fct_chk(output = evbuffer_new());
        // get initial expat allocs out of the way
        fct_req(jw_serializer_create(output, &ser, &err));
        fct_req(jw_serializer_write_start(ser, root, &err));
        jw_serializer_destroy(ser);
        fct_req(jw_serializer_create(output, &ser, &err));
        OOM_RECORD_ALLOCS(jw_serializer_write_start(ser, root, &err))
        OOM_TEST_INIT()
            jw_serializer_destroy(ser);
            fct_req(jw_serializer_create(output, &ser, &err));
        OOM_TEST(&err, jw_serializer_write_start(ser, root, &err))
        jw_serializer_destroy(ser);
        evbuffer_free(output);
        jw_dom_context_destroy(jw_dom_get_context(root));
    } FCT_TEST_END()

    FCT_TEST_BGN(jw_serializer_write_no_mem)
    {
        jw_dom_node     *root;
        jw_err          err;
        struct evbuffer *output;
        jw_serializer   *ser;

        root = _create_simple_node();
        fct_chk(output = evbuffer_new());
        // get initial expat allocs out of the way
        fct_chk(jw_serializer_create(output, &ser, &err));
        fct_req(jw_serializer_write(ser, root, &err))
        jw_serializer_destroy(ser);
        fct_req(jw_serializer_create(output, &ser, &err));
        OOM_RECORD_ALLOCS(jw_serializer_write(ser, root, &err))
        OOM_TEST_INIT()
            jw_serializer_destroy(ser);
            fct_req(jw_serializer_create(output, &ser, &err));
        OOM_TEST(&err, jw_serializer_write(ser, root, &err))
        jw_serializer_destroy(ser);
        evbuffer_free(output);
        jw_dom_context_destroy(jw_dom_get_context(root));
    } FCT_TEST_END()
    FCT_TEST_BGN(jw_parser_create_no_mem)
    {
        jw_parser *xs;
        jw_err err;

        OOM_RECORD_ALLOCS(jw_parser_create(true, &xs, &err))
        jw_parser_destroy(xs);
        OOM_TEST_INIT()
        OOM_TEST(NULL, jw_parser_create(true, &xs, &err))

        OOM_TEST_INIT()
        OOM_TEST(NULL, jw_parser_create(true, &xs, NULL))
    } FCT_TEST_END()
    FCT_TEST_BGN(jw_parser_xml_no_mem)
    {
        jw_dom_node     *root;
        jw_err           err;
        const char *xml =
"<message xmlns='jabber:client' "
         "from='juliet@capulet.net/balcony' "
         "id='some-random-message-id' "
         "to='romeo@montegue.net' "
         "type='chat'>"
    "<thread>some-random-guid</thread>"
    "<body>wherefore art thou, romeo!</body>"
    "<active xmlns='http://jabber.org/protocol/chatstates'/>"
    "<html xmlns='http://jabber.org/protocol/xhtml-im'>"
        "<body xmlns='http://www.w3.org/1999/xhtml'>"
            "<p >wherefore art thou, <strong style='color: blue'>romeo</strong>!</p>"
        "</body>"
    "</html>"
"</message>";

        xml ="<message xmlns='jabber:client' id='message_chat' from='romeo@montegue.net' to='juliet@capulet.net/balcony' type='chat'><body>Hello</body></message>";
        OOM_RECORD_ALLOCS(jw_parse_xml(xml, &root, &err))
        jw_dom_context_destroy(jw_dom_get_context(root));
        OOM_TEST_INIT()
        OOM_TEST(NULL, jw_parse_xml(xml, &root, &err))

        OOM_TEST_INIT()
        OOM_TEST(NULL, jw_parse_xml(xml, &root, NULL))
    } FCT_TEST_END()

    FCT_TEST_BGN(jw_event_dispatcher_create_no_mem)
    {
        jw_event_dispatcher *dispatch;
        void                *source = "the source";
        OOM_SIMPLE_TEST(jw_event_dispatcher_create(
                                source, NULL, &dispatch, &err));
        jw_event_dispatcher_destroy(dispatch);
    } FCT_TEST_END()

    FCT_TEST_BGN(jw_event_create_no_mem)
    {
        jw_event_dispatcher *dispatch;
        jw_err              err;
        void                *source = "the source";
        jw_event            *evt;
        OOM_POOL_TEST_BGN
        fct_chk(jw_event_dispatcher_create(source, NULL, &dispatch, &err));
        OOM_RECORD_ALLOCS(jw_event_dispatcher_create_event(dispatch,
                                             "eventOne",
                                             &evt,
                                             &err))
        OOM_TEST_INIT()
            jw_event_dispatcher_destroy(dispatch);
            fct_chk(jw_event_dispatcher_create(source, NULL, &dispatch, &err));
        OOM_TEST(&err,
                 jw_event_dispatcher_create_event(dispatch,
                                             "eventOne",
                                             &evt,
                                             &err))
        jw_event_dispatcher_destroy(dispatch);
        OOM_POOL_TEST_END

    } FCT_TEST_END()
    FCT_TEST_BGN(jw_event_bind_no_mem)
    {
        jw_event_dispatcher *dispatch;
        jw_err              err;
        void                *source = "the source";
        jw_event            *evt1;
        OOM_POOL_TEST_BGN

        fct_chk(jw_event_dispatcher_create(source, NULL, &dispatch, &err));
        fct_chk(jw_event_dispatcher_create_event(dispatch,
                                                 "eventOne",
                                                 &evt1,
                                                 &err) == true);
        OOM_RECORD_ALLOCS(jw_event_bind(evt1, mock_evt1_callback1, NULL, &err))
        OOM_TEST_INIT()
            jw_event_unbind(evt1, mock_evt1_callback1);
        OOM_TEST(&err, jw_event_bind(evt1, mock_evt1_callback1, NULL, &err))
        jw_event_unbind(evt1, mock_evt1_callback1);
        jw_event_dispatcher_destroy(dispatch);
        OOM_POOL_TEST_END

    } FCT_TEST_END()
    FCT_TEST_BGN(jw_event_trigger_no_mem)
    {
        jw_event_dispatcher *dispatch;
        jw_err              err;
        void                *source = "the source";
        jw_event            *evt1;
        OOM_POOL_TEST_BGN
        fct_chk(jw_event_dispatcher_create(source, NULL, &dispatch, &err));
        fct_chk(jw_event_dispatcher_create_event(dispatch,
                                                 "eventOne",
                                                 &evt1,
                                                 &err) == true);
        OOM_SIMPLE_TEST(jw_event_trigger(evt1, NULL, NULL, NULL, &err))
        jw_event_unbind(evt1, mock_evt1_callback1);
        jw_event_dispatcher_destroy(dispatch);
        OOM_POOL_TEST_END
    } FCT_TEST_END()
} FCTMF_SUITE_END()
