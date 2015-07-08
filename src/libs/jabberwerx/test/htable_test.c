/*
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

#include "fct.h"
#include "test_utils.h"

#include <jabberwerx/util/htable.h>
#include <jabberwerx/util/mem.h>
#include <string.h>


typedef struct _test_walk_data
{
    jw_htable           *table;
    jw_htable_cmpfunc   cmp;
    unsigned int        visited;
    int                 *results;
} walk_data;

int test_htable_nullwalk(void *data, const void *key, void *value)
{
    UNUSED_PARAM(data);
    UNUSED_PARAM(key);
    UNUSED_PARAM(value);
    return 1;
}

int test_htable_stopwalk(void *data, const void *key, void *value)
{
    UNUSED_PARAM(data);
    UNUSED_PARAM(key);
    UNUSED_PARAM(value);
    return 0;
}

int test_htable_walk(void *data, const void *key, void *value)
{
    walk_data *wd = (walk_data*)data;

    wd->results[wd->visited] = (wd->cmp(jw_htable_get(wd->table, key), value) == 0);
    wd->visited++;

    return 1;
}

static void *pvalue;

static void test_htable_store_pvalue(bool replace, bool destroy_key, void *key, void *value)
{
    UNUSED_PARAM(replace);
    UNUSED_PARAM(destroy_key);
    UNUSED_PARAM(key);
    pvalue = value;
}

static bool key_destroy = false;
static void test_htable_destroy_key(bool replace, bool destroy_key, void *key, void *value)
{
    UNUSED_PARAM(replace);
    if (destroy_key)
    {
        free(key);
        key_destroy = true;
    }
    free(value);
}

static bool _oom_test(jw_err *err)
{
    jw_htable *table;

    // initial bucket count of 1 to force a resize and increase coverage
    if (!jw_htable_create(1, jw_str_hashcode, jw_str_compare, &table, err))
    {
        return false;
    }

    if (!jw_htable_put(table, "key1", "value one", NULL, err)
     || !jw_htable_put(table, "key1", "value one again", NULL, err)
     || !jw_htable_put(table, "key2", "value two", NULL, err)
     || !jw_htable_put(table, "key3", "value three", NULL, err)
     || !jw_htable_put(table, "key4", "value four", NULL, err))
    {
        jw_htable_destroy(table);
        return false;
    }

    if (4 != jw_htable_get_count(table))
    {
        jw_htable_destroy(table);
        return false;
    }

    jw_htable_destroy(table);

    return true;
}


FCTMF_SUITE_BGN(htable_test)
{
    FCT_TEST_BGN(jw_htable_hash_str)
    {
        /* simply test that the hashcodes are different/same */
        fct_chk(jw_str_hashcode("key1") == jw_str_hashcode("key1"));
        fct_chk(jw_str_hashcode("key2") != jw_str_hashcode("key1"));
        fct_chk(jw_str_hashcode("Key1") != jw_str_hashcode("key1"));
        fct_chk(jw_str_hashcode("KEY1") != jw_str_hashcode("key1"));
        fct_chk(jw_str_hashcode("KEY_ONE") != jw_str_hashcode("key1"));
        fct_chk(jw_str_hashcode("") != jw_str_hashcode("key1"));

        fct_chk(jw_str_compare("key1", "key1") == 0);
        fct_chk(jw_str_compare("key2", "key1") > 0);
        fct_chk(jw_str_compare("Key1", "key1") < 0);
        fct_chk(jw_str_compare("KEY1", "key1") < 0);
        fct_chk(jw_str_compare("KEY_ONE", "key1") < 0);
        fct_chk(jw_str_compare("", "key1") < 0);
    }FCT_TEST_END()

    FCT_TEST_BGN(jw_htable_hash_strcase)
    {
        /* simply test that the hashcodes are different/same */
        fct_chk(jw_strcase_hashcode("key1") == jw_strcase_hashcode("key1"));
        fct_chk(jw_strcase_hashcode("key2") != jw_strcase_hashcode("key1"));
        fct_chk(jw_strcase_hashcode("Key1") == jw_strcase_hashcode("key1"));
        fct_chk(jw_strcase_hashcode("KEY1") == jw_strcase_hashcode("key1"));
        fct_chk(jw_strcase_hashcode("KEY_ONE") != jw_strcase_hashcode("key1"));
        fct_chk(jw_strcase_hashcode("") != jw_strcase_hashcode("key1"));

        fct_chk(jw_strcase_compare("key1", "key1") == 0);
        fct_chk(jw_strcase_compare("key2", "key1") > 0);
        fct_chk(jw_strcase_compare("Key1", "key1") == 0);
        fct_chk(jw_strcase_compare("KEY1", "key1") == 0);
        fct_chk(jw_strcase_compare("KEY_ONE", "key1") > 0);
        fct_chk(jw_strcase_compare("", "key1") < 0);
    } FCT_TEST_END()

    FCT_TEST_BGN(jw_htable_hash_int)
    {
        /* simply test that the hashcodes are different/same */
        fct_chk(jw_int_hashcode((void*)25) == jw_int_hashcode((void*)25));
        fct_chk(jw_int_hashcode((void*)42) != jw_int_hashcode((void*)25));
        fct_chk(jw_int_hashcode((void*)-1231) != jw_int_hashcode((void*)25));
        fct_chk(jw_int_hashcode((void*)0) != jw_int_hashcode((void*)25));
        fct_chk(jw_int_hashcode((void*)1236423) != jw_int_hashcode((void*)25));

        fct_chk(jw_int_compare((void*)25, (void*)25) == 0);
        fct_chk(jw_int_compare((void*)42, (void*)25) > 0);
        fct_chk(jw_int_compare((void*)-1231, (void*)25) < 0);
        fct_chk(jw_int_compare((void*)0, (void*)25) < 0);
        fct_chk(jw_int_compare((void*)1236423, (void*)25) > 0);
    } FCT_TEST_END()

    FCT_TEST_BGN(jw_htable_create_destroy)
    {
        jw_htable   *table;
        jw_err      err;

        fct_chk(jw_htable_create(7,
                                 jw_int_hashcode,
                                 jw_int_compare,
                                 &table,
                                 &err));
        fct_chk(table);

        jw_htable_destroy(table);
        fct_chk(1); /* confirm we did not assert */
    } FCT_TEST_END()

    FCT_TEST_BGN(jw_htable_basics)
    {
        jw_htable   *table;
        jw_err      err;
        fct_chk(jw_htable_create(7,
                                 jw_str_hashcode,
                                 jw_str_compare,
                                 &table,
                                 &err));

        fct_chk(jw_htable_get_count(table) == 0);
        fct_chk(jw_htable_get(table, "key1") == NULL);
        fct_chk(jw_htable_get(table, "key2") == NULL);

        pvalue = NULL;
        fct_chk(jw_htable_put(table, "key1", "value one", test_htable_store_pvalue, &err));
        fct_chk(pvalue == NULL);
        fct_chk(jw_htable_get_count(table) == 1);
        fct_chk(strcmp(jw_htable_get(table, "key1"), "value one") == 0);
        fct_chk(jw_htable_get(table, "key2") == NULL);

        fct_chk(jw_htable_put(table, "key2", "value two", test_htable_store_pvalue, &err));
        fct_chk(pvalue == NULL);
        fct_chk(jw_htable_get_count(table) == 2);
        fct_chk(strcmp(jw_htable_get(table, "key1"), "value one") == 0);
        fct_chk(strcmp(jw_htable_get(table, "key2"), "value two") == 0);

        fct_chk(jw_htable_put(table, "key1", "val 1", test_htable_store_pvalue, &err));
        fct_chk(strcmp((const char *)pvalue, "value one") == 0);
        fct_chk(jw_htable_get_count(table) == 2);
        fct_chk(strcmp(jw_htable_get(table, "key1"), "val 1") == 0);
        fct_chk(strcmp(jw_htable_get(table, "key2"), "value two") == 0);

        pvalue = NULL;
        jw_htable_remove(table, "key1");
        fct_chk(strcmp(pvalue, "val 1") == 0);
        fct_chk(jw_htable_get_count(table) == 1);
        fct_chk(jw_htable_get(table, "key1") == NULL);
        fct_chk(strcmp(jw_htable_get(table, "key2"), "value two") == 0);

        pvalue = NULL;
        fct_chk(jw_htable_put(table, "key1", "first value", test_htable_store_pvalue, &err));
        fct_chk(pvalue == NULL);
        fct_chk(jw_htable_get_count(table) == 2);
        fct_chk(strcmp(jw_htable_get(table, "key1"), "first value") == 0);
        fct_chk(strcmp(jw_htable_get(table, "key2"), "value two") == 0);

        jw_htable_clear(table);
        fct_chk(jw_htable_get_count(table) == 0);
        fct_chk(jw_htable_get(table, "key1") == NULL);
        fct_chk(jw_htable_get(table, "key2") == NULL);

        jw_htable_destroy(table);
    } FCT_TEST_END()

    FCT_TEST_BGN(jw_htable_node)
    {
        jw_htable   *table;
        jw_hnode    *node;
        jw_err      err;
        fct_chk(jw_htable_create(7,
                                 jw_str_hashcode,
                                 jw_str_compare,
                                 &table,
                                 &err));

        jw_htable_put(table, "key1", "value one", test_htable_store_pvalue, &err);
        jw_htable_put(table, "key2", "value two", test_htable_store_pvalue, &err);
        jw_htable_put(table, "key3", "value three", test_htable_store_pvalue, &err);

        node = jw_htable_get_node(table, "key1");
        fct_chk(strcmp(jw_hnode_get_key(node), "key1") == 0);
        fct_chk(strcmp(jw_hnode_get_value(node), "value one") == 0);

        pvalue = NULL;
        jw_hnode_put_value(node, "val1", test_htable_store_pvalue);
        fct_chk(strcmp(pvalue, "value one") == 0);
        fct_chk(strcmp(jw_hnode_get_value(node), "val1") == 0);
        
        pvalue = NULL;
        jw_hnode_put_value(node, "value 1", test_htable_store_pvalue);
        fct_chk(strcmp(pvalue, "val1") == 0);
        fct_chk(strcmp(jw_hnode_get_value(node), "value 1") == 0);
        
        pvalue = NULL;
        jw_hnode_put_value(node, "first value", NULL);
        fct_chk(strcmp(pvalue, "value 1") == 0);
        fct_chk(strcmp(jw_hnode_get_value(node), "first value") == 0);

        pvalue = NULL;
        jw_hnode_put_value(node, "value #1", test_htable_store_pvalue);
        fct_chk(NULL == pvalue);
        fct_chk(strcmp(jw_hnode_get_value(node), "value #1") == 0);

        jw_htable_remove_node(table, node);
        fct_chk_eq_int(jw_htable_get_count(table), 2);

        jw_htable_destroy(table);
    } FCT_TEST_END()

    FCT_TEST_BGN(jw_htable_iteration)
    {
        jw_htable    *table;
        jw_hnode     *node;
        unsigned int count;
        jw_err       err;

        // initial bucket count of 1 to force a resize and increase coverage
        fct_req(jw_htable_create(
                            1, jw_str_hashcode, jw_str_compare, &table, &err));

        node = jw_htable_get_first_node(table);
        fct_chk(node == NULL);

        fct_req(jw_htable_put(table, "key1", jw_data_strdup("value one"),
                              jw_htable_free_data_cleaner, NULL));
        fct_req(jw_htable_put(table, "key2", jw_data_strdup("value two"),
                              jw_htable_free_data_cleaner, NULL));
        fct_req(jw_htable_put(table, "key3", jw_data_strdup("value three"),
                              jw_htable_free_data_cleaner, NULL));

        count = 1;
        node = jw_htable_get_first_node(table);
        while ((node = jw_htable_get_next_node(table, node)) != NULL)
        {
            count++;
            fct_chk(jw_hnode_get_key(node) != NULL);
            fct_chk(jw_hnode_get_value(node) != NULL);
        }
        fct_chk(count == jw_htable_get_count(table));

        jw_htable_remove(table, "key2");

        count = 1;
        node = jw_htable_get_first_node(table);
        while ((node = jw_htable_get_next_node(table, node)) != NULL)
        {
            count++;
            fct_chk(jw_hnode_get_key(node) != NULL);
            fct_chk(jw_hnode_get_value(node) != NULL);
        }
        fct_chk(count == jw_htable_get_count(table));

        jw_htable_destroy(table);
    } FCT_TEST_END()

    FCT_TEST_BGN(jw_htable_walk)
    {
        jw_htable    *table;
        walk_data    wd;
        unsigned int idx;
        jw_err       err;

        fct_chk(jw_htable_create(7,
                                 jw_str_hashcode,
                                 jw_str_compare,
                                 &table,
                                 &err));

        fct_chk(jw_htable_put(table, "key1", "value one", NULL, &err));
        fct_chk(jw_htable_put(table, "key2", "value two", NULL, &err));
        fct_chk(jw_htable_put(table, "key3", "value three", NULL, &err));
        wd.table = table;
        wd.cmp = jw_str_compare;
        wd.visited = 0;
        wd.results = (int*)malloc(3 * sizeof(int));

        jw_htable_walk(table, test_htable_walk, &wd);
        fct_chk(jw_htable_get_count(table) == wd.visited);
        idx = 0;
        while (idx < wd.visited)
        {
            fct_chk(wd.results[idx++]);
        }

        free(wd.results);
        jw_htable_destroy(table);
    } FCT_TEST_END()

    FCT_TEST_BGN(jw_htable_collisions)
    {
        jw_htable    *table;
        jw_hnode     *nodea, *nodeb, *node;

        // "09Vi" and "08vJ" collide, which WILL change if the string hashcode
        // function changes
        char *a = "09Vi";
        char *b = "08vJ";

        fct_chk(jw_htable_create(5,
                                 jw_str_hashcode,
                                 jw_str_compare,
                                 &table,
                                 NULL));

        fct_chk_eq_int(jw_str_hashcode(a), jw_str_hashcode(b));
        fct_chk(jw_htable_put(table, a, "1", NULL, NULL));
        fct_chk(jw_htable_get(table, b) == NULL);
        fct_chk(jw_htable_put(table, b, "2", NULL, NULL));
        fct_chk(jw_htable_get(table, b) != NULL);
        fct_chk(jw_htable_get(table, a) != NULL);
        fct_chk_eq_int(jw_htable_walk(table, test_htable_nullwalk, NULL), 2);
        fct_chk_eq_int(jw_htable_walk(table, test_htable_stopwalk, NULL), 1);

        nodea = jw_htable_get_node(table, a);
        nodeb = jw_htable_get_node(table, b);
        node = jw_htable_get_next_node(table, nodea);
        if (node != NULL)
        {
            fct_chk(node == nodeb);
        }
        else
        {
            node = jw_htable_get_next_node(table, nodeb);
            fct_chk(node == nodea);
        }

        jw_htable_remove(table, "non-existant");
        jw_htable_remove(table, a);
        fct_chk(jw_htable_put(table, a, "3", NULL, NULL));
        jw_htable_remove(table, b);
        jw_htable_remove(table, a);

        jw_htable_destroy(table);
    } FCT_TEST_END()

    FCT_TEST_BGN(jw_htable_cleaner_edges)
    {
        jw_htable    *table;
        jw_err       err;

        fct_chk(jw_htable_create(-1,
                                 jw_str_hashcode,
                                 jw_str_compare,
                                 &table,
                                 &err));
        fct_chk_eq_int(jw_htable_walk(table, test_htable_nullwalk, NULL), 0);
        fct_chk(jw_htable_put(table, "key1", "value one", NULL, &err));
        fct_chk(jw_htable_put(table, "key1", "value one prime", NULL, &err));
        fct_chk(jw_htable_put(table, "key1", NULL, NULL, &err));
        fct_chk(jw_htable_put(table, "key1", "value one", NULL, &err));
        jw_htable_remove(table, "key1");
        fct_chk(jw_htable_put(table, "key1", NULL, NULL, &err));
        jw_htable_remove(table, "key1");
        fct_chk(jw_htable_put(table, "key1", "value one", NULL, &err));
        jw_htable_clear(table);
        jw_htable_destroy(table);
    } FCT_TEST_END()

    FCT_TEST_BGN(jw_htable_destroy_key)
    {
        jw_htable    *table;
        jw_err       err;

        fct_chk(jw_htable_create(-1,
                                 jw_str_hashcode,
                                 jw_str_compare,
                                 &table,
                                 &err));
        key_destroy = false;
        char *k = strdup("key1");
        fct_chk(jw_htable_put(table, k, strdup("value one"), test_htable_destroy_key, &err));
        fct_chk(!key_destroy);
        fct_chk(jw_htable_put(table, k, strdup("value two"), test_htable_destroy_key, &err));
        fct_chk(!key_destroy);
        fct_chk(jw_htable_put(table, strdup(k), strdup("value two"), test_htable_destroy_key, &err));
        fct_chk(key_destroy);
        key_destroy = false;
        jw_htable_destroy(table);
        fct_chk(key_destroy);
     } FCT_TEST_END()

    FCT_TEST_BGN(jw_htable_oom)
    {
        OOM_SIMPLE_TEST(_oom_test(&err));
        OOM_TEST_INIT();
        OOM_TEST(NULL, _oom_test(NULL));
    } FCT_TEST_END()
} FCTMF_SUITE_END()
