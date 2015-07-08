/**
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

#include "fct.h"
#include <jabberwerx/dom.h>
#include <jabberwerx/util/log.h>
#include <jabberwerx/util/parser.h>
#include <jabberwerx/util/str.h>
#include "../src/include/dom_int.h"

#include <stdint.h>

static jw_dom_ctx   *g_ctx;


// not static since this is used in other test suites
bool _dom_equal(jw_dom_node *expected, jw_dom_node *actual, bool deep)
{
    if (expected == actual)
    {
        return true;
    }
    if (expected == NULL)
    {
        jw_log(JW_LOG_DEBUG, "expected == NULL");
        return false;
    }
    if (actual == NULL)
    {
        jw_log(JW_LOG_DEBUG, "actual == NULL");
        return false;
    }

    jw_dom_nodetype type = jw_dom_get_nodetype(expected);
    if (type != jw_dom_get_nodetype(actual))
    {
        jw_log(JW_LOG_DEBUG, "type != jw_dom_get_nodetype(actual)");
        return false;
    }
    if (0 != jw_strcmp(jw_dom_get_ename(expected), jw_dom_get_ename(actual)))
    {
        jw_log(JW_LOG_DEBUG, "jw_strcmp(jw_dom_get_ename(expected), jw_dom_get_ename(actual)) != 0");
        return false;
    }
    if (0 != jw_strcmp(jw_dom_get_value(expected), jw_dom_get_value(actual)))
    {
        jw_log(JW_LOG_DEBUG, "jw_strcmp(jw_dom_get_value(expected), jw_dom_get_value(actual)) != 0");
        return false;
    }

    if (type == JW_DOM_TYPE_ELEMENT)
    {
        jw_dom_node *expItr = jw_dom_get_first_namespace(expected);
        jw_dom_node *actItr = jw_dom_get_first_namespace(actual);
        while (expItr != NULL && actItr != NULL)
        {
            if (!_dom_equal(expItr, actItr, deep))
            {
                return false;
            }

            expItr = jw_dom_get_sibling(expItr);
            actItr = jw_dom_get_sibling(actItr);
        }

        // should both be NULL here
        if (expItr != actItr)
        {
            jw_log(JW_LOG_DEBUG, "nss: expItr(%s) != actItr(%s)",
                   expItr ? jw_dom_get_value(expItr) : NULL,
                   actItr ? jw_dom_get_value(actItr) : NULL);
            return false;
        }

        expItr = jw_dom_get_first_attribute(expected);
        actItr = jw_dom_get_first_attribute(actual);
        while (NULL != expItr && NULL != actItr)
        {
            if (!_dom_equal(expItr, actItr, deep))
            {
                return false;
            }

            expItr = jw_dom_get_sibling(expItr);
            actItr = jw_dom_get_sibling(actItr);
        }

        // should both be NULL here
        if (expItr != actItr)
        {
            jw_log(JW_LOG_DEBUG, "expItr != actItr)");
            return false;
        }

        expItr = jw_dom_get_first_child(expected);
        actItr = jw_dom_get_first_child(actual);
        if (deep)
        {
            while (NULL != expItr && NULL != actItr)
            {
                if (!_dom_equal(expItr, actItr, deep))
                {
                    return false;
                }

                expItr = jw_dom_get_sibling(expItr);
                actItr = jw_dom_get_sibling(actItr);
            }

            // should both be NULL here
            if (expItr != actItr)
            {
                jw_log(JW_LOG_DEBUG, "children: expItr != actItr)");
                return false;
            }
        }
        else if (actItr != NULL)
        {
            jw_log(JW_LOG_DEBUG, "children: NULL != actItr)");
            return false;
        }
    }

    return true;
}

static bool _domsEqual(jw_dom_ctx  *owner,
                       jw_dom_node *expected,
                       jw_dom_node *actual,
                       bool        deep)
{
    if (!_dom_equal(expected, actual, deep))
    {
        return false;
    }

    if (jw_dom_get_context(actual) != owner)
    {
        jw_log(JW_LOG_DEBUG, "jw_dom_get_context(actual) != owner");
        return false;
    }

    return true;
}

static bool _mallocCalled = false;
static void *_dom_test_malloc(size_t size)
{
    _mallocCalled = true;
    return malloc(size);
}

static void *_dom_test_realloc(void *ptr, size_t size)
{
    _mallocCalled = true;
    return realloc(ptr, size);
}

static bool _freeCalled = false;
static void _dom_test_free(void *ptr)
{
    _freeCalled = true;
    free(ptr);
}


FCTMF_FIXTURE_SUITE_BGN(dom_test)
{
    FCT_SETUP_BGN()
    {
        jw_dom_context_create(&g_ctx, NULL);
    } FCT_SETUP_END()
    FCT_TEARDOWN_BGN()
    {
        jw_dom_context_destroy(g_ctx);
    } FCT_TEARDOWN_END()

    FCT_TEST_BGN(jw_dom_context_create_destroy)
    {
        jw_dom_ctx  *ctx = NULL;
        jw_err      err;

        fct_chk(jw_dom_context_create(&ctx, &err) == true);
        fct_chk(ctx != NULL);
        fct_chk(jw_dom_context_get_pool(ctx) != NULL);

        jw_dom_context_destroy(ctx);
    } FCT_TEST_END()

    FCT_TEST_BGN(jw_dom_create_text)
    {
        jw_dom_node *txt;
        jw_err      err;

        fct_chk(jw_dom_text_create(g_ctx,
                                   "this is a text node",
                                   &txt,
                                   &err) == true);
        fct_chk_eq_int(jw_dom_get_nodetype(txt), JW_DOM_TYPE_TEXT);
        fct_chk_eq_str(jw_dom_get_value(txt), "this is a text node");
        fct_chk(jw_dom_get_context(txt) == g_ctx);
        fct_chk(jw_dom_get_parent(txt) == NULL);
        fct_chk(jw_dom_get_ename(txt) == NULL);
    } FCT_TEST_END()
    // test fix for DE699: issue creating text nodes with UTF8
    FCT_TEST_BGN(jw_dom_create_text_utf8)
    {
        jw_dom_node *txt;
        jw_err      err;

        fct_req(jw_dom_text_create(g_ctx,
                                   "王菲章子怡",
                                   &txt,
                                   &err) == true);
        fct_chk_eq_int(jw_dom_get_nodetype(txt), JW_DOM_TYPE_TEXT);
        fct_chk_eq_str(jw_dom_get_value(txt), "王菲章子怡");
        fct_chk(jw_dom_get_context(txt) == g_ctx);
        fct_chk(jw_dom_get_parent(txt) == NULL);
        fct_chk(jw_dom_get_ename(txt) == NULL);

        fct_req(jw_dom_text_create(g_ctx,
                                   "aзәрбајҹан",
                                   &txt,
                                   &err) == true);
        fct_chk_eq_int(jw_dom_get_nodetype(txt), JW_DOM_TYPE_TEXT);
        fct_chk_eq_str(jw_dom_get_value(txt), "aзәрбајҹан");
        fct_chk(jw_dom_get_context(txt) == g_ctx);
        fct_chk(jw_dom_get_parent(txt) == NULL);
        fct_chk(jw_dom_get_ename(txt) == NULL);

        fct_req(jw_dom_text_create(g_ctx,
                                   "специальных",
                                   &txt,
                                   &err) == true);
        fct_chk_eq_int(jw_dom_get_nodetype(txt), JW_DOM_TYPE_TEXT);
        fct_chk_eq_str(jw_dom_get_value(txt), "специальных");
        fct_chk(jw_dom_get_context(txt) == g_ctx);
        fct_chk(jw_dom_get_parent(txt) == NULL);
        fct_chk(jw_dom_get_ename(txt) == NULL);

        //failures from jwcunicode examples,
        /*
          From Unicode 3.2 http://www.unicode.org/reports/tr28/tr28-3.html
          Table 3.1B Legal UTF-8 Byte Sequences

          1rst Byte     2nd Byte        3rd Byte        4th Byte
            00..7F

            C2..DF      80..BF

            E0          A0..BF          80..BF
            E1..EC      80..BF          80..BF
            ED          80..9F          80..BF
            EE..EF      80..BF          80..BF

            F0          90..BF          80..BF          80..BF
            F1..F3      80..BF          80..BF          80..BF
            F4          80..8F          80..BF          80..BF
                            ^ note 8 not B
            F5..F7      80..BF          80..BF          80..BF ??

            F8..FB      80..BFx4

            FC..FD      80..BFx5

        */
        //use jw_dom_text_create to test unicode, avoid xml validation
        uint8_t s_invalid_utf8[]  = { 0xf0, 0x80, 0xbf, 0x80, 0x00 };
        uint8_t s_overlong_utf8[] = { 0xc0, 0xbc, 0x00 };
        uint8_t s_3byte_e0[] = { 0xe0, 0x8f, 0xbf, 0x00 };
        uint8_t s_3byte_e0_pass_1[] = { 0xe0, 0xa0, 0xbf, 0x00 };
        uint8_t s_3byte_e0_pass_2[] = { 0xe0, 0xbf, 0xbf, 0x00 };
        uint8_t s_3byte_ed[] = { 0xed, 0xbf, 0xbf, 0x00 };
        uint8_t s_3byte_ed_pass_1[] = { 0xed, 0x9f, 0xbf, 0x00 };
        uint8_t s_3byte_ed_pass_2[] = { 0xed, 0x80, 0xbf, 0x00 };
        uint8_t s_4byte_f0[] = { 0xf0, 0x8f, 0xbf, 0xbf, 0x00 };
        uint8_t s_4byte_f0_1[] = { 0xf0, 0xc0, 0xbf, 0xbf, 0x00 };
        uint8_t s_4byte_f0_pass_1[] = { 0xf0, 0x90, 0xbf, 0xbf, 0x00 };
        uint8_t s_4byte_f0_pass_2[] = { 0xf0, 0xa5, 0x95, 0x9c, 0x00 };
        uint8_t s_4byte_f0_pass_3[] = { 0xf0, 0xbf, 0x80, 0xbf, 0x00 };
        uint8_t s_4byte_f4[] = { 0xf4, 0x90, 0xbf, 0xbf, 0x00 };
        uint8_t s_4byte_f4_pass_1[] = { 0xf4, 0x8e, 0xbf, 0xbf, 0x00 };
        uint8_t s_4byte_f4_pass_2[] = { 0xf4, 0x8f, 0xbf, 0xbf, 0x00 };
        uint8_t s_6byte_good[] = { 0xfd, 0x80, 0xbf, 0xbf, 0x90, 0xb0, 0x00 };
        uint8_t s_6byte_bad[]  = { 0xfd, 0x80, 0xbf, 0xbf, 0x0a, 0x0a, 0x00 };
        uint8_t s_valid_chinese[] = { 0xe5, 0x90, 0x89, 0xe7, 0xa5, 0xa5, 0xe5, 0xa6,
                                      0x82, 0xe6, 0x84, 0x8f, 0x00 }; // 吉祥如意
        uint8_t s_valid_multilang[] = { 0xe5, 0x9c, 0x8b, 0xe8, 0xaa, 0x9e, 0x2d, 0x74,
                                        0x69, 0xe1, 0xba, 0xbf, 0x6e, 0x67, 0x20, 0x56,
                                        0x69, 0xe1, 0xbb, 0x87, 0x74, 0x2d, 0xed, 0x95,
                                        0xad, 0xea, 0xb8, 0x80, 0x2d, 0xd1, 0x80, 0xd1,
                                        0x83, 0xd1, 0x81, 0xd1, 0x81, 0xd0, 0xba, 0xd0,
                                        0xb8, 0xd0, 0xb9, 0x20, 0xd1, 0x8f, 0xd0, 0xb7,
                                        0xd1, 0x8b, 0xd0, 0xba, 0x00 }; // 國語-tiếng Việt-항글-русский язык

        err.code = JW_ERR_NONE;
        fct_chk(jw_dom_text_create(g_ctx,
                                   (char *)s_invalid_utf8,
                                   &txt,
                                   &err) == false);
        fct_chk(err.code == JW_ERR_INVALID_ARG);
        err.code = JW_ERR_NONE;
        fct_chk(jw_dom_text_create(g_ctx,
                                   (char *)s_overlong_utf8,
                                   &txt,
                                   &err) == false);
        fct_chk(err.code == JW_ERR_INVALID_ARG);
        err.code = JW_ERR_NONE;
        fct_chk(jw_dom_text_create(g_ctx,
                                   (char *)s_3byte_e0,
                                   &txt,
                                   &err) == false);
        fct_chk(jw_dom_text_create(g_ctx,
                                   (char *)s_3byte_e0_pass_1,
                                   &txt,
                                   &err) == true);
        fct_chk(jw_dom_text_create(g_ctx,
                                   (char *)s_3byte_e0_pass_2,
                                   &txt,
                                   &err) == true);
        fct_chk(err.code == JW_ERR_INVALID_ARG);
        err.code = JW_ERR_NONE;
        fct_chk(jw_dom_text_create(g_ctx,
                                   (char *)s_3byte_ed,
                                   &txt,
                                   &err) == false);
        fct_chk(err.code == JW_ERR_INVALID_ARG);
        fct_chk(jw_dom_text_create(g_ctx,
                                   (char *)s_3byte_ed_pass_1,
                                   &txt,
                                   &err) == true);
        fct_chk(jw_dom_text_create(g_ctx,
                                   (char *)s_3byte_ed_pass_2,
                                   &txt,
                                   &err) == true);
        err.code = JW_ERR_NONE;
        fct_chk(jw_dom_text_create(g_ctx,
                                   (char *)s_4byte_f0,
                                   &txt,
                                   &err) == false);
        fct_chk(err.code == JW_ERR_INVALID_ARG);
        err.code = JW_ERR_NONE;
        fct_chk(jw_dom_text_create(g_ctx,
                                   (char *)s_4byte_f0_1,
                                   &txt,
                                   &err) == false);
        fct_chk(err.code == JW_ERR_INVALID_ARG);
        fct_chk(jw_dom_text_create(g_ctx,
                                   (char *)s_4byte_f0_pass_1,
                                   &txt,
                                   &err) == true);
        fct_chk(jw_dom_text_create(g_ctx,
                                   (char *)s_4byte_f0_pass_2,
                                   &txt,
                                   &err) == true);
        fct_chk(jw_dom_text_create(g_ctx,
                                   (char *)s_4byte_f0_pass_3,
                                   &txt,
                                   &err) == true);

        err.code = JW_ERR_NONE;
        fct_chk(jw_dom_text_create(g_ctx,
                                   (char *)s_4byte_f4,
                                   &txt,
                                   &err) == false);
        fct_chk(err.code == JW_ERR_INVALID_ARG);
        fct_chk(jw_dom_text_create(g_ctx,
                                   (char *)s_4byte_f4_pass_1,
                                   &txt,
                                   &err) == true);
        fct_chk(jw_dom_text_create(g_ctx,
                                   (char *)s_4byte_f4_pass_2,
                                   &txt,
                                   &err) == true);

        err.code = JW_ERR_NONE;
        fct_chk(jw_dom_text_create(g_ctx,
                                   (char *)s_6byte_bad,
                                   &txt,
                                   &err) == false);
        fct_chk(err.code == JW_ERR_INVALID_ARG);
        fct_chk(jw_dom_text_create(g_ctx,
                                   (char *)s_6byte_good,
                                   &txt,
                                   &err) == true);

        fct_chk(jw_dom_text_create(g_ctx,
                                   (char *)s_valid_chinese,
                                   &txt,
                                   &err) == true);
        fct_chk(jw_dom_text_create(g_ctx,
                                   (char *)s_valid_multilang,
                                   &txt,
                                   &err) == true);
    } FCT_TEST_END()

    FCT_TEST_BGN(jw_dom_create_element)
    {
        jw_dom_node *elem;
        jw_err      err;

        fct_chk(jw_dom_element_create(g_ctx,
                                      "{jabber:client}message",
                                      &elem,
                                      &err) == true);
        fct_chk(jw_dom_get_context(elem) == g_ctx);
        fct_chk(jw_dom_get_parent(elem) == NULL);
        fct_chk_eq_int(jw_dom_get_nodetype(elem), JW_DOM_TYPE_ELEMENT);
        fct_chk_eq_str(jw_dom_get_ename(elem), "{jabber:client}message");
        fct_chk_eq_str(jw_dom_get_localname(elem), "message");
        fct_chk_eq_str(jw_dom_get_namespace_uri(elem), "jabber:client");

        fct_chk(jw_dom_element_create(g_ctx,
                                      "{jabber:client}meSSageOne",
                                      &elem,
                                      &err) == true);
        fct_chk(jw_dom_get_context(elem) == g_ctx);
        fct_chk(jw_dom_get_parent(elem) == NULL);
        fct_chk_eq_int(jw_dom_get_nodetype(elem), JW_DOM_TYPE_ELEMENT);
        fct_chk_eq_str(jw_dom_get_ename(elem), "{jabber:client}meSSageOne");
        fct_chk_eq_str(jw_dom_get_localname(elem), "meSSageOne");
        fct_chk_eq_str(jw_dom_get_namespace_uri(elem), "jabber:client");
    } FCT_TEST_END()
    FCT_TEST_BGN(jw_dom_element_create_bad_ename)
    {
        jw_dom_node *elem = NULL;
        jw_err      err;

        /* invalid localname */
        fct_chk(jw_dom_element_create(g_ctx,
                                      "{jabber:client}bad message",
                                      &elem,
                                      &err) == false);
        fct_chk_eq_int(err.code, JW_ERR_INVALID_ARG);
        fct_chk(elem == NULL);

        /* missing localname */
        fct_chk(jw_dom_element_create(g_ctx,
                                      "{jabber:client}",
                                      &elem,
                                      &err) == false);
        fct_chk_eq_int(err.code, JW_ERR_INVALID_ARG);
        fct_chk(elem == NULL);

        /* non-terminated namespace */
        fct_chk(jw_dom_element_create(g_ctx,
                                      "{jabber:clientmessage",
                                      &elem,
                                      &err) == false);
        fct_chk_eq_int(err.code, JW_ERR_INVALID_ARG);
        fct_chk(elem == NULL);

        /* missing namespace */
        fct_chk(jw_dom_element_create(g_ctx,
                                      "message",
                                      &elem,
                                      &err) == false);
        fct_chk_eq_int(err.code, JW_ERR_INVALID_ARG);
        fct_chk(elem == NULL);

    } FCT_TEST_END()

    FCT_TEST_BGN(jw_dom_create_element_invalid_arg)
    {
        jw_dom_node *elem;
        jw_err      err;

        fct_chk(jw_dom_element_create(g_ctx,
                                      "{jabber:client}:message",
                                      &elem,
                                      &err) == false);
        fct_chk_eq_int(err.code, JW_ERR_INVALID_ARG);

        fct_chk(jw_dom_element_create(g_ctx,
                                      "{jabber:client}MeSSage One",
                                      &elem,
                                      &err) == false);
        fct_chk_eq_int(err.code, JW_ERR_INVALID_ARG);

        // valid utf8; invalid XML NameStartChar (related to DE699)
        fct_chk(jw_dom_element_create(g_ctx,
                                      "{jabber:client}\0xcc\0x80abc",
                                      &elem,
                                      &err) == false);

        // valid utf8; invalid XML NameChar (related to DE699)
        fct_chk(jw_dom_element_create(g_ctx,
                                      "{jabber:client}ab;",
                                      &elem,
                                      &err) == false);
        } FCT_TEST_END()
     /**
     * test DE699: Validate support for utf-8 characters
     */
    FCT_TEST_BGN(jw_dom_validate_utf8_test)
    {
        jw_dom_node *elem, *child;
        jw_err      err;

        // valid 3-bytes Tamil utf8 chars
        fct_chk(jw_dom_element_create(g_ctx,
                                      "{jabber:client}சாப்பிடுவேன்",
                                      &elem,
                                      &err) == true);

        // valid 2-bytes Arabic utf8 chars; valid XML
        fct_chk(jw_dom_element_create(g_ctx,
                                      "{jabber:client}ئؔؔؔوسػشي",
                                      &elem,
                                      &err) == true);
        // valid 4-bytes Chinese utf-8 chars; valid xml
        fct_chk(jw_dom_element_create(g_ctx,
                                      "{jabber:client}我能吞下玻璃而不傷",
                                      &elem,
                                      &err) == true);

        fct_chk(jw_dom_element_create(g_ctx,
                                      "{jabber:client}𐆆𐆄𐆔𐌘𐌙𐐵𐑛𐑺𥂝𥃨𥅘𥕜",
                                      &elem,
                                      &err) == true);

        //valid utf-8; accented cyrillic
        fct_chk(jw_dom_element_create(g_ctx,
                                      "{jabber:client}ейпомисли́си",
                                      &elem,
                                      &err) == true);
        //valid utf-8; valid startNMChars and nameChars
        fct_chk(jw_dom_element_create(g_ctx,
                                      "{jabber:client}_ab-.c7",
                                      &elem,
                                      &err) == true);
        //valid utf-8; combining diacritical marks
        fct_chk(jw_dom_element_create(g_ctx,
                                      "{jabber:client}àÅb̌̐d̨e͋͋f͑ͼh̶̫",
                                      &elem,
                                      &err) == true);
        //Valid utf-8; set attribute name
        fct_chk(jw_dom_set_attribute(elem,
                                     "{}From",
                                     "fεKςτD户*pzd€&amp;aχdb)μ_",
                                     &err) == true);
        //valid utf-8; create text node
        fct_req(jw_dom_text_create(g_ctx,
                                   "εيVpX&gt;Dς用@7vXf,س",
                                   &child,
                                   &err) == true);
        //valid utf-8; invalid XML(no-break space)
        fct_chk(jw_dom_element_create(g_ctx,
                                      "{jabber:client}\0xe2\0x89\0xa0",
                                      &elem,
                                      &err) == false);
        fct_chk_eq_int(err.code, JW_ERR_INVALID_ARG);
    } FCT_TEST_END()
    FCT_TEST_BGN(jw_dom_element_namespaces)
    {
        jw_dom_node *elem;
        jw_dom_node *ns;
        jw_err      err;

        fct_req(jw_dom_element_create(g_ctx,
                                      "{http://etherx.jabber.org/streams}stream",
                                      &elem,
                                      &err) == true);

        fct_chk(jw_dom_get_first_namespace(elem) == NULL);
        fct_chk(jw_dom_find_namespace_uri(elem, "stream") == NULL);
        fct_chk(jw_dom_find_namespace_prefix(elem, "http://etherx.jabber.org/streams") == NULL);
        fct_chk(jw_dom_find_namespace_uri(elem, "") == NULL);
        fct_chk(jw_dom_find_namespace_prefix(elem, "jabber:client") == NULL);

        fct_chk(jw_dom_put_namespace(elem,
                                     "stream",
                                     "http://etherx.jabber.org/streams",
                                     &err) == true);
        ns = jw_dom_get_first_namespace(elem);
        fct_chk(ns != NULL);
        fct_chk_eq_int(jw_dom_get_nodetype(ns), JW_DOM_TYPE_NAMESPACE);
        fct_chk(jw_dom_get_context(ns) == g_ctx);
        fct_chk(jw_dom_get_parent(ns) == elem);
        fct_chk_eq_str(jw_dom_get_ename(ns), "stream");
        fct_chk_eq_str(jw_dom_get_value(ns), "http://etherx.jabber.org/streams");
        fct_chk_eq_str(jw_dom_find_namespace_uri(elem, "stream"), "http://etherx.jabber.org/streams");
        fct_chk_eq_str(jw_dom_find_namespace_prefix(elem, "http://etherx.jabber.org/streams"), "stream");
        fct_chk(jw_dom_find_namespace_uri(elem, "") == NULL);
        fct_chk(jw_dom_find_namespace_prefix(elem, "jabber:client") == NULL);

        fct_chk(jw_dom_put_namespace(elem,
                                     "",
                                     "jabber:client",
                                     &err) == true);
        ns = jw_dom_get_first_namespace(elem);
        fct_chk(ns != NULL);
        fct_chk_eq_int(jw_dom_get_nodetype(ns), JW_DOM_TYPE_NAMESPACE);
        fct_chk(jw_dom_get_context(ns) == g_ctx);
        fct_chk(jw_dom_get_parent(ns) == elem);
        fct_chk_eq_str(jw_dom_get_ename(ns), "stream");
        fct_chk_eq_str(jw_dom_get_value(ns), "http://etherx.jabber.org/streams");
        ns = jw_dom_get_sibling(ns);
        fct_chk(ns != NULL);
        fct_chk_eq_int(jw_dom_get_nodetype(ns), JW_DOM_TYPE_NAMESPACE);
        fct_chk(jw_dom_get_context(ns) == g_ctx);
        fct_chk(jw_dom_get_parent(ns) == elem);
        fct_chk_eq_str(jw_dom_get_ename(ns), "");
        fct_chk_eq_str(jw_dom_get_value(ns), "jabber:client");
        fct_chk_eq_str(jw_dom_find_namespace_uri(elem, "stream"), "http://etherx.jabber.org/streams");
        fct_chk_eq_str(jw_dom_find_namespace_prefix(elem, "http://etherx.jabber.org/streams"), "stream");
        fct_chk_eq_str(jw_dom_find_namespace_uri(elem, ""), "jabber:client");
        fct_chk_eq_str(jw_dom_find_namespace_prefix(elem, "jabber:client"), "");

        fct_chk(jw_dom_put_namespace(elem,
                                     "stream",
                                     "http://etherx.jabber.org/flash",
                                     &err) == true);
        ns = jw_dom_get_first_namespace(elem);
        fct_chk(ns != NULL);
        fct_chk_eq_int(jw_dom_get_nodetype(ns), JW_DOM_TYPE_NAMESPACE);
        fct_chk(jw_dom_get_context(ns) == g_ctx);
        fct_chk(jw_dom_get_parent(ns) == elem);
        fct_chk_eq_str(jw_dom_get_ename(ns), "stream");
        fct_chk_eq_str(jw_dom_get_value(ns), "http://etherx.jabber.org/flash");
        ns = jw_dom_get_sibling(ns);
        fct_chk(ns != NULL);
        fct_chk_eq_int(jw_dom_get_nodetype(ns), JW_DOM_TYPE_NAMESPACE);
        fct_chk(jw_dom_get_context(ns) == g_ctx);
        fct_chk(jw_dom_get_parent(ns) == elem);
        fct_chk_eq_str(jw_dom_get_ename(ns), "");
        fct_chk_eq_str(jw_dom_get_value(ns), "jabber:client");
        fct_chk_eq_str(jw_dom_find_namespace_uri(elem, "stream"), "http://etherx.jabber.org/flash");
        fct_chk_eq_str(jw_dom_find_namespace_prefix(elem, "http://etherx.jabber.org/flash"), "stream");
        fct_chk(jw_dom_find_namespace_prefix(elem, "http://etherx.jabber.org/streams") == NULL);
        fct_chk_eq_str(jw_dom_find_namespace_uri(elem, ""), "jabber:client");
        fct_chk_eq_str(jw_dom_find_namespace_prefix(elem, "jabber:client"), "");

        fct_chk(jw_dom_put_namespace(elem,
                                     "stream",
                                     NULL,
                                     &err) == true);
        ns = jw_dom_get_first_namespace(elem);
        fct_chk(ns != NULL);
        fct_chk_eq_int(jw_dom_get_nodetype(ns), JW_DOM_TYPE_NAMESPACE);
        fct_chk(jw_dom_get_context(ns) == g_ctx);
        fct_chk(jw_dom_get_parent(ns) == elem);
        fct_chk_eq_str(jw_dom_get_ename(ns), "");
        fct_chk_eq_str(jw_dom_get_value(ns), "jabber:client");
        fct_chk(jw_dom_find_namespace_uri(elem, "stream") == NULL);
        fct_chk(jw_dom_find_namespace_prefix(elem, "http://etherx.jabber.org/flash") == NULL);
        fct_chk(jw_dom_find_namespace_prefix(elem, "http://etherx.jabber.org/streams") == NULL);
        fct_chk_eq_str(jw_dom_find_namespace_uri(elem, ""), "jabber:client");
        fct_chk_eq_str(jw_dom_find_namespace_prefix(elem, "jabber:client"), "");
    } FCT_TEST_END()

    FCT_TEST_BGN(jw_dom_element_namespaces_invalid_arg)
    {
        jw_dom_node *elem;
        jw_dom_node *ns;
        jw_err      err;

        fct_req(jw_dom_element_create(g_ctx,
                                      "{http://etherx.jabber.org/streams}stream",
                                      &elem,
                                      &err) == true);
        fct_chk(jw_dom_put_namespace(elem,
                                     "stream:",
                                     "http://etherx.jabber.org/streams",
                                     &err) == false);
        fct_chk_eq_int(err.code, JW_ERR_INVALID_ARG);

        fct_chk(jw_dom_get_first_namespace(elem) == NULL);
        fct_chk(jw_dom_find_namespace_uri(elem, "stream") == NULL);
        fct_chk(jw_dom_find_namespace_prefix(elem, "http://etherx.jabber.org/streams") == NULL);
        fct_chk(jw_dom_find_namespace_uri(elem, "") == NULL);
        fct_chk(jw_dom_find_namespace_prefix(elem, "jabber:client") == NULL);
        fct_chk(jw_dom_put_namespace(elem,
                                     "stream",
                                     "http://etherx.jabber.org/streams",
                                     &err) == true);
        ns = jw_dom_get_first_namespace(elem);
        fct_chk(ns != NULL);
        fct_chk_eq_int(jw_dom_get_nodetype(ns), JW_DOM_TYPE_NAMESPACE);
        fct_chk(jw_dom_get_context(ns) == g_ctx);
        fct_chk(jw_dom_get_parent(ns) == elem);
        fct_chk_eq_str(jw_dom_get_ename(ns), "stream");
        fct_chk_eq_str(jw_dom_get_value(ns), "http://etherx.jabber.org/streams");
        fct_chk_eq_str(jw_dom_find_namespace_uri(elem, "stream"), "http://etherx.jabber.org/streams");
        fct_chk_eq_str(jw_dom_find_namespace_prefix(elem, "http://etherx.jabber.org/streams"), "stream");


        fct_chk(jw_dom_put_namespace(elem,
                                     "xml",
                                     "",
                                     &err) == false);
        fct_chk_eq_int(err.code, JW_ERR_INVALID_ARG);
        ns = jw_dom_get_first_namespace(elem);
        fct_chk(ns != NULL);
        fct_chk_eq_int(jw_dom_get_nodetype(ns), JW_DOM_TYPE_NAMESPACE);
        fct_chk(jw_dom_get_context(ns) == g_ctx);
        fct_chk(jw_dom_get_parent(ns) == elem);
        fct_chk_eq_str(jw_dom_get_ename(ns), "stream");
        fct_chk_eq_str(jw_dom_get_value(ns), "http://etherx.jabber.org/streams");

        memset(&err, 0, sizeof(jw_err));
        fct_chk(jw_dom_put_namespace(elem,
                                     "xml",
                                     "http://www.w3.org/XML/1998/namespace1",
                                     &err) == false);
        fct_chk_eq_int(err.code, JW_ERR_INVALID_ARG);

        memset(&err, 0, sizeof(jw_err));
        fct_chk(jw_dom_put_namespace(elem,
                                     "xml",
                                     "http://www.w3.org/XML/1998/namespace",
                                     &err) == true);
        fct_chk_eq_int(err.code, JW_ERR_NONE);

        memset(&err, 0, sizeof(jw_err));
        fct_chk(jw_dom_put_namespace(elem,
                                     "XML",
                                     "http://www.w3.org/XML/1998/namespace",
                                     &err) == false);
        fct_chk_eq_int(err.code, JW_ERR_INVALID_ARG);
        } FCT_TEST_END()
    FCT_TEST_BGN(jw_dom_element_namespace_find)
    {
        jw_dom_node *elem, *parent, *root;
        jw_err      err;

        fct_req(jw_dom_element_create(g_ctx,
                                      "{http://etherx.jabber.org/streams}stream",
                                      &root,
                                      &err) == true);
        fct_req(jw_dom_element_create(g_ctx,
                                      "{jabber:client}message",
                                      &parent,
                                      &err) == true);
        fct_req(jw_dom_add_child(root, parent, &err) == true);
        fct_req(jw_dom_element_create(g_ctx,
                                      "{http://jabber.org/protocol/pubsub#event}event",
                                      &elem,
                                      &err) == true);
        fct_req(jw_dom_add_child(parent, elem, &err) == true);

        fct_chk(jw_dom_put_namespace(root,
                                     "stream",
                                     "http://etherx.jabber.org/streams",
                                     &err) == true);
        fct_chk(jw_dom_put_namespace(root,
                                     "",
                                     "jabber:client",
                                     &err) == true);
        fct_chk(jw_dom_put_namespace(parent,
                                     "",
                                     "jabber:client",
                                     &err) == true);
        fct_chk(jw_dom_put_namespace(elem,
                                     "",
                                     "http://jabber.org/protocol/pubsub#event",
                                     &err) == true);

        fct_chk_eq_str(jw_dom_find_namespace_uri(elem, ""),
                       "http://jabber.org/protocol/pubsub#event");
        fct_chk_eq_str(jw_dom_find_namespace_uri(elem, "stream"),
                       "http://etherx.jabber.org/streams");
        fct_chk_eq_str(jw_dom_find_namespace_prefix(elem, "http://jabber.org/protocol/pubsub#event"),
                       "");
        fct_chk_eq_str(jw_dom_find_namespace_prefix(elem, "http://etherx.jabber.org/streams"),
                       "stream");
        fct_chk_eq_str(jw_dom_find_namespace_prefix(elem, "jabber:client"),
                       "");

        fct_chk(jw_dom_put_namespace(parent,
                                     "",
                                     NULL,
                                     &err) == true);
        fct_chk_eq_str(jw_dom_find_namespace_uri(elem, ""),
                       "http://jabber.org/protocol/pubsub#event");
        fct_chk_eq_str(jw_dom_find_namespace_uri(elem, "stream"),
                       "http://etherx.jabber.org/streams");
        fct_chk_eq_str(jw_dom_find_namespace_prefix(elem, "http://jabber.org/protocol/pubsub#event"),
                       "");
        fct_chk_eq_str(jw_dom_find_namespace_prefix(elem, "http://etherx.jabber.org/streams"),
                       "stream");
        fct_chk_eq_str(jw_dom_find_namespace_prefix(elem, "jabber:client"),
                       "");

        fct_chk(jw_dom_put_namespace(root,
                                     "",
                                     "jabber:server",
                                     &err) == true);
        fct_chk_eq_str(jw_dom_find_namespace_uri(elem, ""),
                       "http://jabber.org/protocol/pubsub#event");
        fct_chk_eq_str(jw_dom_find_namespace_uri(elem, "stream"),
                       "http://etherx.jabber.org/streams");
        fct_chk_eq_str(jw_dom_find_namespace_prefix(elem, "http://jabber.org/protocol/pubsub#event"),
                       "");
        fct_chk_eq_str(jw_dom_find_namespace_prefix(elem, "http://etherx.jabber.org/streams"),
                       "stream");
        fct_chk_eq_str(jw_dom_find_namespace_prefix(elem, "jabber:server"),
                       "");
        fct_chk(jw_dom_find_namespace_prefix(elem, "jabber:client") == NULL);

        fct_chk(jw_dom_put_namespace(parent,
                                     "",
                                     "jabber:client",
                                     &err) == true);
        fct_chk_eq_str(jw_dom_find_namespace_uri(elem, ""),
                       "http://jabber.org/protocol/pubsub#event");
        fct_chk_eq_str(jw_dom_find_namespace_uri(elem, "stream"),
                       "http://etherx.jabber.org/streams");
        fct_chk_eq_str(jw_dom_find_namespace_prefix(elem, "http://jabber.org/protocol/pubsub#event"),
                       "");
        fct_chk_eq_str(jw_dom_find_namespace_prefix(elem, "http://etherx.jabber.org/streams"),
                       "stream");
        fct_chk_eq_str(jw_dom_find_namespace_prefix(elem, "jabber:server"),
                       "");
        fct_chk_eq_str(jw_dom_find_namespace_prefix(elem, "jabber:client"),
                       "");
    } FCT_TEST_END()

    FCT_TEST_BGN(jw_dom_element_attributes)
    {
        jw_dom_node *elem;
        jw_dom_node *attr;
        jw_err      err;

        fct_req(jw_dom_element_create(g_ctx,
                                      "{jabber:client}message",
                                      &elem,
                                      &err) == true);

        fct_chk(jw_dom_get_first_attribute(elem) == NULL);
        fct_chk(jw_dom_get_attribute(elem, "{}from") == NULL);
        fct_chk(jw_dom_get_attribute(elem, "from") == NULL);

        fct_chk(jw_dom_set_attribute(elem,
                                     "{}from",
                                     "romeo@montegue.net",
                                     &err) == true);
        attr = jw_dom_get_first_attribute(elem);
        fct_chk(attr != NULL);
        fct_chk_eq_int(jw_dom_get_nodetype(attr), JW_DOM_TYPE_ATTRIBUTE);
        fct_chk(jw_dom_get_context(attr) == g_ctx);
        fct_chk(jw_dom_get_parent(attr) == elem);
        fct_chk_eq_str(jw_dom_get_ename(attr), "{}from");
        fct_chk_eq_str(jw_dom_get_localname(attr), "from");
        fct_chk_eq_str(jw_dom_get_namespace_uri(attr), "");
        fct_chk_eq_str(jw_dom_get_value(attr), "romeo@montegue.net");
        fct_chk_eq_str(jw_dom_get_attribute(elem, "{}from"), "romeo@montegue.net");
        fct_chk_eq_str(jw_dom_get_attribute(elem, "from"), "romeo@montegue.net");

        fct_chk(jw_dom_set_attribute(elem,
                                     "{}from",
                                     "benvolio@montegue.net",
                                     &err) == true);
        fct_chk_eq_int(jw_dom_get_nodetype(attr), JW_DOM_TYPE_ATTRIBUTE);
        fct_chk(jw_dom_get_context(attr) == g_ctx);
        fct_chk(jw_dom_get_parent(attr) == elem);
        fct_chk_eq_str(jw_dom_get_ename(attr), "{}from");
        fct_chk_eq_str(jw_dom_get_localname(attr), "from");
        fct_chk_eq_str(jw_dom_get_namespace_uri(attr), "");
        fct_chk_eq_str(jw_dom_get_value(attr), "benvolio@montegue.net");
        fct_chk_eq_str(jw_dom_get_attribute(elem, "{}from"), "benvolio@montegue.net");
        fct_chk_eq_str(jw_dom_get_attribute(elem, "from"), "benvolio@montegue.net");

        fct_chk(jw_dom_set_attribute(elem,
                                     "{}from",
                                     NULL,
                                     &err) == true);
        fct_chk(jw_dom_get_attribute(elem, "{}from") == NULL);
        fct_chk(jw_dom_get_attribute(elem, "from") == NULL);
        fct_chk(jw_dom_get_first_attribute(elem) == NULL);

        fct_chk(jw_dom_set_attribute(elem,
                                     "{}FroMySelF",
                                     "test@example.com",
                                     &err) == true);
        attr = jw_dom_get_first_attribute(elem);
        fct_chk(attr != NULL);
        fct_chk_eq_int(jw_dom_get_nodetype(attr), JW_DOM_TYPE_ATTRIBUTE);
        fct_chk(jw_dom_get_context(attr) == g_ctx);
        fct_chk(jw_dom_get_parent(attr) == elem);
        fct_chk_eq_str(jw_dom_get_ename(attr), "{}FroMySelF");
        fct_chk_eq_str(jw_dom_get_localname(attr), "FroMySelF");
        fct_chk_eq_str(jw_dom_get_namespace_uri(attr), "");
        fct_chk_eq_str(jw_dom_get_value(attr), "test@example.com");
        fct_chk_eq_str(jw_dom_get_attribute(elem, "{}FroMySelF"), "test@example.com");
        fct_chk_eq_str(jw_dom_get_attribute(elem, "FroMySelF"), "test@example.com");
        fct_chk(jw_dom_get_attribute(elem, "{}fromyself") == NULL);

        // validate fix for DE699: Issue creating attributes with utf8
        fct_chk(jw_dom_set_attribute(elem,
                                     "{}FroMySelF",
                                     "王菲章子怡",
                                     &err) == true);
        attr = jw_dom_get_first_attribute(elem);
        fct_chk(attr != NULL);
        fct_chk_eq_int(jw_dom_get_nodetype(attr), JW_DOM_TYPE_ATTRIBUTE);
        fct_chk(jw_dom_get_context(attr) == g_ctx);
        fct_chk(jw_dom_get_parent(attr) == elem);
        fct_chk_eq_str(jw_dom_get_ename(attr), "{}FroMySelF");
        fct_chk_eq_str(jw_dom_get_localname(attr), "FroMySelF");
        fct_chk_eq_str(jw_dom_get_namespace_uri(attr), "");
        fct_chk_eq_str(jw_dom_get_value(attr), "王菲章子怡");
        fct_chk_eq_str(jw_dom_get_attribute(elem, "{}FroMySelF"), "王菲章子怡");
        fct_chk_eq_str(jw_dom_get_attribute(elem, "FroMySelF"), "王菲章子怡");
        fct_chk(jw_dom_get_attribute(elem, "{}fromyself") == NULL);

        fct_chk(jw_dom_set_attribute(elem,
                                     "{}FroMySelF",
                                     "aзәрбајҹан",
                                     &err) == true);
        attr = jw_dom_get_first_attribute(elem);
        fct_chk(attr != NULL);
        fct_chk_eq_int(jw_dom_get_nodetype(attr), JW_DOM_TYPE_ATTRIBUTE);
        fct_chk(jw_dom_get_context(attr) == g_ctx);
        fct_chk(jw_dom_get_parent(attr) == elem);
        fct_chk_eq_str(jw_dom_get_ename(attr), "{}FroMySelF");
        fct_chk_eq_str(jw_dom_get_localname(attr), "FroMySelF");
        fct_chk_eq_str(jw_dom_get_namespace_uri(attr), "");
        fct_chk_eq_str(jw_dom_get_value(attr), "aзәрбајҹан");
        fct_chk_eq_str(jw_dom_get_attribute(elem, "{}FroMySelF"), "aзәрбајҹан");
        fct_chk_eq_str(jw_dom_get_attribute(elem, "FroMySelF"), "aзәрбајҹан");
        fct_chk(jw_dom_get_attribute(elem, "{}fromyself") == NULL);

        fct_chk(jw_dom_set_attribute(elem,
                                     "{}FroMySelF",
                                     "специальных",
                                     &err) == true);
        attr = jw_dom_get_first_attribute(elem);
        fct_chk(attr != NULL);
        fct_chk_eq_int(jw_dom_get_nodetype(attr), JW_DOM_TYPE_ATTRIBUTE);
        fct_chk(jw_dom_get_context(attr) == g_ctx);
        fct_chk(jw_dom_get_parent(attr) == elem);
        fct_chk_eq_str(jw_dom_get_ename(attr), "{}FroMySelF");
        fct_chk_eq_str(jw_dom_get_localname(attr), "FroMySelF");
        fct_chk_eq_str(jw_dom_get_namespace_uri(attr), "");
        fct_chk_eq_str(jw_dom_get_value(attr), "специальных");
        fct_chk_eq_str(jw_dom_get_attribute(elem, "{}FroMySelF"), "специальных");
        fct_chk_eq_str(jw_dom_get_attribute(elem, "FroMySelF"), "специальных");
        fct_chk(jw_dom_get_attribute(elem, "{}fromyself") == NULL);
    } FCT_TEST_END()

    FCT_TEST_BGN(jw_dom_attribute_bad_ename)
    {
        jw_dom_node     *elem;
        jw_err          err;

        fct_req(jw_dom_element_create(g_ctx,
                                      "{jabber:client}message",
                                      &elem,
                                      &err) == true);

        /* invalid localname */
        fct_chk(jw_dom_set_attribute(elem,
                                     "{}bad id",
                                     "id",
                                     &err) == false);
        fct_chk_eq_int(err.code, JW_ERR_INVALID_ARG);

        /* missing localname */
        fct_chk(jw_dom_set_attribute(elem,
                                     "{}",
                                     "id",
                                     &err) == false);
        fct_chk_eq_int(err.code, JW_ERR_INVALID_ARG);

        /* non-terminated namespace */
        fct_chk(jw_dom_set_attribute(elem,
                                     "{id",
                                     "id",
                                     &err) == false);
        fct_chk_eq_int(err.code, JW_ERR_INVALID_ARG);

        /* missing namespace */
        fct_chk(jw_dom_set_attribute(elem,
                                     "id",
                                     "id",
                                     &err) == false);
        fct_chk_eq_int(err.code, JW_ERR_INVALID_ARG);

        /* invalid character */
        fct_chk(jw_dom_set_attribute(elem,
                                     "\0xe2\0x89\0xa0",
                                     "id",
                                     &err) == false);
        fct_chk_eq_int(err.code, JW_ERR_INVALID_ARG);

    } FCT_TEST_END()

    FCT_TEST_BGN(jw_dom_element_attributes_invalid_arg)
    {
        jw_dom_node *elem;
        jw_err err;

        fct_chk(jw_dom_element_create(g_ctx,
                                      "{jabber:client}message",
                                      &elem,
                                      &err) == true);

        fct_chk(jw_dom_get_first_attribute(elem) == NULL);

        fct_chk(jw_dom_set_attribute(elem,
                                     "{}:from",
                                     "test@example.com",
                                     &err) == false);
        fct_chk_eq_int(err.code, JW_ERR_INVALID_ARG);
        fct_chk(jw_dom_get_first_attribute(elem) == NULL);

        fct_chk(jw_dom_set_attribute(elem,
                                     "{}Message From:",
                                     "test@example.com",
                                     &err) == false);
        fct_chk_eq_int(err.code, JW_ERR_INVALID_ARG);

        // valid UTF8; invalid NameStartChar (related to DE699)
        fct_chk(jw_dom_set_attribute(elem,
                                     "{}\0xcc\0x80abc",
                                     "test@example.com",
                                     &err) == false);
        fct_chk_eq_int(err.code, JW_ERR_INVALID_ARG);

        // valid utf8; invalid XML NameChar (related to DE699)
        fct_chk(jw_dom_set_attribute(elem,
                                     "{jabber:client}ab;",
                                     "test@example.com",
                                     &err) == false);
    } FCT_TEST_END()

    FCT_TEST_BGN(jw_dom_attribute_walk)
    {
        jw_dom_node     *elem;
        jw_dom_node     *attr, *remAttr;
        jw_err          err;

        fct_req(jw_dom_element_create(g_ctx,
                                      "{jabber:client}message",
                                      &elem,
                                      &err) == true);

        fct_req(jw_dom_set_attribute(elem,
                                     "{}id",
                                     "message_chat_12345678",
                                     &err) == true);
        fct_req(jw_dom_set_attribute(elem,
                                     "{}from",
                                     "romeo@montegue.net",
                                     &err) == true);
        fct_req(jw_dom_set_attribute(elem,
                                     "{}to",
                                     "juliet@capulet.net/balcony",
                                     &err) == true);
        fct_req(jw_dom_set_attribute(elem,
                                     "{}type",
                                     "chat",
                                     &err) == true);
        attr = jw_dom_get_first_attribute(elem);
        fct_chk(attr != NULL);
        fct_chk_eq_int(jw_dom_get_nodetype(attr), JW_DOM_TYPE_ATTRIBUTE);
        fct_chk(jw_dom_get_context(attr) == g_ctx);
        fct_chk(jw_dom_get_parent(attr) == elem);
        fct_chk_eq_str(jw_dom_get_ename(attr), "{}id");
        fct_chk_eq_str(jw_dom_get_value(attr), "message_chat_12345678");
        fct_chk_eq_str(jw_dom_get_attribute(elem, "{}id"), "message_chat_12345678");
        attr = jw_dom_get_sibling(attr);
        fct_chk(attr != NULL);
        fct_chk_eq_int(jw_dom_get_nodetype(attr), JW_DOM_TYPE_ATTRIBUTE);
        fct_chk(jw_dom_get_context(attr) == g_ctx);
        fct_chk(jw_dom_get_parent(attr) == elem);
        fct_chk_eq_str(jw_dom_get_ename(attr), "{}from");
        fct_chk_eq_str(jw_dom_get_value(attr), "romeo@montegue.net");
        fct_chk_eq_str(jw_dom_get_attribute(elem, "{}from"), "romeo@montegue.net");
        remAttr = attr = jw_dom_get_sibling(attr);
        fct_chk(attr != NULL);
        fct_chk_eq_int(jw_dom_get_nodetype(attr), JW_DOM_TYPE_ATTRIBUTE);
        fct_chk(jw_dom_get_context(attr) == g_ctx);
        fct_chk(jw_dom_get_parent(attr) == elem);
        fct_chk_eq_str(jw_dom_get_ename(attr), "{}to");
        fct_chk_eq_str(jw_dom_get_value(attr), "juliet@capulet.net/balcony");
        fct_chk_eq_str(jw_dom_get_attribute(elem, "{}to"), "juliet@capulet.net/balcony");
        attr = jw_dom_get_sibling(attr);
        fct_chk(attr != NULL);
        fct_chk_eq_int(jw_dom_get_nodetype(attr), JW_DOM_TYPE_ATTRIBUTE);
        fct_chk(jw_dom_get_context(attr) == g_ctx);
        fct_chk(jw_dom_get_parent(attr) == elem);
        fct_chk_eq_str(jw_dom_get_ename(attr), "{}type");
        fct_chk_eq_str(jw_dom_get_value(attr), "chat");
        fct_chk_eq_str(jw_dom_get_attribute(elem, "{}type"), "chat");

        /* remove by direct detach */
        jw_dom_detach(remAttr);
        attr = jw_dom_get_first_attribute(elem);
        fct_chk(attr != NULL);
        fct_chk_eq_int(jw_dom_get_nodetype(attr), JW_DOM_TYPE_ATTRIBUTE);
        fct_chk(jw_dom_get_context(attr) == g_ctx);
        fct_chk(jw_dom_get_parent(attr) == elem);
        fct_chk_eq_str(jw_dom_get_ename(attr), "{}id");
        fct_chk_eq_str(jw_dom_get_value(attr), "message_chat_12345678");
        fct_chk_eq_str(jw_dom_get_attribute(elem, "{}id"), "message_chat_12345678");
        attr = jw_dom_get_sibling(attr);
        fct_chk(attr != NULL);
        fct_chk_eq_int(jw_dom_get_nodetype(attr), JW_DOM_TYPE_ATTRIBUTE);
        fct_chk(jw_dom_get_context(attr) == g_ctx);
        fct_chk(jw_dom_get_parent(attr) == elem);
        fct_chk_eq_str(jw_dom_get_ename(attr), "{}from");
        fct_chk_eq_str(jw_dom_get_value(attr), "romeo@montegue.net");
        fct_chk_eq_str(jw_dom_get_attribute(elem, "{}from"), "romeo@montegue.net");
        attr = jw_dom_get_sibling(attr);
        fct_chk(attr != NULL);
        fct_chk_eq_int(jw_dom_get_nodetype(attr), JW_DOM_TYPE_ATTRIBUTE);
        fct_chk(jw_dom_get_context(attr) == g_ctx);
        fct_chk(jw_dom_get_parent(attr) == elem);
        fct_chk_eq_str(jw_dom_get_ename(attr), "{}type");
        fct_chk_eq_str(jw_dom_get_value(attr), "chat");
        fct_chk_eq_str(jw_dom_get_attribute(elem, "{}type"), "chat");

        /* remove by indirect lookup and clear */
        fct_chk(jw_dom_set_attribute(elem,
                                     "{}id",
                                     NULL,
                                     &err) == true);
        attr = jw_dom_get_first_attribute(elem);
        fct_chk(attr != NULL);
        fct_chk_eq_int(jw_dom_get_nodetype(attr), JW_DOM_TYPE_ATTRIBUTE);
        fct_chk(jw_dom_get_context(attr) == g_ctx);
        fct_chk(jw_dom_get_parent(attr) == elem);
        fct_chk_eq_str(jw_dom_get_ename(attr), "{}from");
        fct_chk_eq_str(jw_dom_get_value(attr), "romeo@montegue.net");
        fct_chk_eq_str(jw_dom_get_attribute(elem, "{}from"), "romeo@montegue.net");
        attr = jw_dom_get_sibling(attr);
        fct_chk(attr != NULL);
        fct_chk_eq_int(jw_dom_get_nodetype(attr), JW_DOM_TYPE_ATTRIBUTE);
        fct_chk(jw_dom_get_context(attr) == g_ctx);
        fct_chk(jw_dom_get_parent(attr) == elem);
        fct_chk_eq_str(jw_dom_get_ename(attr), "{}type");
        fct_chk_eq_str(jw_dom_get_value(attr), "chat");
        fct_chk_eq_str(jw_dom_get_attribute(elem, "{}type"), "chat");
    } FCT_TEST_END()

    FCT_TEST_BGN(jw_dom_children)
    {
        jw_dom_node     *grandparent, *parent;
        jw_dom_node     *children[2];
        jw_dom_node     *childItr;
        jw_err          err;

        fct_chk(jw_dom_element_create(g_ctx,
                                      "{http://etherx.jabber.org/streams}stream",
                                      &grandparent,
                                      &err) == true);
        fct_chk(jw_dom_element_create(g_ctx,
                                      "{jabber:client}message",
                                      &parent,
                                      &err) == true);
        fct_chk(jw_dom_element_create(g_ctx,
                                      "{jabber:client}body",
                                      &children[0],
                                      &err) == true);
        fct_chk(jw_dom_text_create(g_ctx,
                                   "hello there",
                                   &children[1],
                                   &err) == true);

        fct_chk(jw_dom_add_child(parent, children[0], &err) == true);
        childItr = jw_dom_get_first_child(parent);
        fct_chk(jw_dom_get_parent(children[0]) == parent);
        fct_chk(childItr == children[0]);

        fct_chk(jw_dom_remove_child(parent, children[0], &err) == true);
        fct_chk(jw_dom_get_parent(children[0]) == NULL);
        fct_chk(jw_dom_get_first_child(parent) == NULL);

        fct_chk(jw_dom_add_child(children[0], children[1], &err) == true);
        childItr = jw_dom_get_first_child(children[0]);
        fct_chk(jw_dom_get_parent(children[1]) == children[0]);
        fct_chk(childItr = children[1]);

        fct_chk(jw_dom_remove_child(children[0], children[1], &err) == true);
        fct_chk(jw_dom_get_parent(children[1]) == NULL);
        fct_chk(jw_dom_get_first_child(children[0]) == NULL);

        fct_chk(jw_dom_add_child(parent, children[0], &err) == true);
        fct_chk(jw_dom_get_parent(children[0]) == parent);
        fct_chk(jw_dom_add_child(grandparent, parent, &err) == true);
        fct_chk(jw_dom_get_parent(parent) == grandparent);

        fct_chk(jw_dom_add_child(children[0], grandparent, &err) == false);
        fct_chk_eq_int(err.code, JW_ERR_INVALID_ARG);
    } FCT_TEST_END()

    FCT_TEST_BGN(jw_dom_children_invalid_arg)
    {
        jw_dom_node     *parent;
        jw_dom_node     *child1, *child2, *child3, *child4;
        jw_err          err;

        fct_chk(jw_dom_element_create(g_ctx,
                                      "{jabber:client}message",
                                      &parent,
                                      &err) == true);
        fct_chk(jw_dom_element_create(g_ctx,
                                      "{jabber:client}subject",
                                      &child1,
                                      &err) == true);
        fct_chk(jw_dom_element_create(g_ctx,
                                      "{jabber:client}body",
                                      &child2,
                                      &err) == true);
        fct_req(jw_dom_text_create(g_ctx, "foo!", &child3, &err) == true);

        fct_req(jw_dom_text_create(g_ctx, "ξμθΛΔ", &child4, &err) == true);

        fct_chk(jw_dom_add_child(parent, child1, &err) == true);
        fct_chk(jw_dom_get_parent(child1) == parent);

        fct_chk(jw_dom_add_child(child1, child2, &err) == true);
        fct_chk(jw_dom_get_parent(child2) == child1);

        fct_chk(jw_dom_add_child(child2, parent, &err) == false);
        fct_chk_eq_int(err.code, JW_ERR_INVALID_ARG);

        fct_chk(jw_dom_remove_child(child2, child1, &err) == false);
        fct_chk_eq_int(err.code, JW_ERR_INVALID_ARG);

        fct_chk(jw_dom_remove_child(child2, child2, &err) == false);
        fct_chk_eq_int(err.code, JW_ERR_INVALID_ARG);
    } FCT_TEST_END()

    FCT_TEST_BGN(jw_dom_element_lookup)
    {
        jw_dom_node     *parent;
        jw_dom_node     *children[5];
        jw_dom_node     *childItr;
        int             idx;
        jw_err          err;

        fct_req(jw_dom_element_create(g_ctx,
                                      "{jabber:client}message",
                                      &parent,
                                      &err) == true);
        fct_req(jw_dom_element_create(g_ctx,
                                      "{urn:dumb:protocol}body",
                                      &children[0],
                                      &err) == true);
        fct_req(jw_dom_element_create(g_ctx,
                                      "{jabber:client}thread",
                                      &children[1],
                                      &err) == true);
        fct_req(jw_dom_element_create(g_ctx,
                                      "{jabber:client}body",
                                      &children[2],
                                      &err) == true);
        fct_req(jw_dom_element_create(g_ctx,
                                      "{http://jabber.org/protocol/chatstates}active",
                                      &children[3],
                                      &err) == true);
        fct_req(jw_dom_element_create(g_ctx,
                                      "{jabber:x:oob}x",
                                      &children[4],
                                      &err) == true);
        for (idx = 0; idx < 5; idx++)
        {
            fct_req(jw_dom_add_child(parent, children[idx], &err) == true);
        }

        childItr = jw_dom_get_first_element(parent, NULL);
        fct_chk(childItr == children[0]);
        childItr = jw_dom_get_first_element(parent, "{jabber:client}thread");
        fct_chk(childItr == children[1]);
        childItr = jw_dom_get_first_element(parent, "{jabber:client}body");
        fct_chk(childItr == children[2]);
        childItr = jw_dom_get_first_element(parent, "{urn:dumb:protocol}body");
        fct_chk(childItr == children[0]);
        childItr = jw_dom_get_first_element(parent, "{http://jabber.org/protocol/chatstates}active");
        fct_chk(childItr == children[3]);
        childItr = jw_dom_get_first_element(parent, "{jabber:x:oob}x");
        fct_chk(childItr == children[4]);
        childItr = jw_dom_get_first_element(parent, "{jabber:client}");
        fct_chk(childItr == children[1]);
        childItr = jw_dom_get_first_element(parent, "{urn:dumb:protocol}");
        fct_chk(childItr == children[0]);
        childItr = jw_dom_get_first_element(parent, "{http://jabber.org/protocol/chatstates}");
        fct_chk(childItr == children[3]);
        childItr = jw_dom_get_first_element(parent, "{jabber:x:oob}");
        fct_chk(childItr == children[4]);
        childItr = jw_dom_get_first_element(parent, "thread");
        fct_chk(childItr == children[1]);
        childItr = jw_dom_get_first_element(parent, "body");
        fct_chk(childItr == children[0]);
        childItr = jw_dom_get_first_element(parent, "active");
        fct_chk(childItr == children[3]);
        childItr = jw_dom_get_first_element(parent, "x");
        fct_chk(childItr == children[4]);
    } FCT_TEST_END()

    FCT_TEST_BGN(jw_dom_children_walk)
    {
        jw_dom_node     *parent;
        jw_dom_node     *children[5];
        jw_dom_node     *childItr;
        jw_err          err;

        fct_req(jw_dom_element_create(g_ctx,
                                      "{http://www.w3.org/1999/xhtml}div",
                                      &parent,
                                      &err) == true);
        fct_req(jw_dom_element_create(g_ctx,
                                      "{http://www.w3.org/1999/xhtml}span",
                                      &children[0],
                                      &err) == true);
        fct_req(jw_dom_text_create(g_ctx,
                                   "hello there, ",
                                   &children[1],
                                   &err) == true);
        fct_req(jw_dom_element_create(g_ctx,
                                      "{http://www.w3.org/1999/xhtml}b",
                                      &children[2],
                                      &err) == true);
        fct_req(jw_dom_element_create(g_ctx,
                                      "{http://www.w3.org/1999/xhtml}span",
                                      &children[3],
                                      &err) == true);
        fct_req(jw_dom_text_create(g_ctx,
                                   "foo!",
                                   &children[4],
                                   &err) == true);

        fct_chk(jw_dom_add_child(parent, children[0], &err) == true);
        fct_chk(jw_dom_add_child(parent, children[1], &err) == true);
        fct_chk(jw_dom_add_child(parent, children[2], &err) == true);
        fct_chk(jw_dom_add_child(parent, children[3], &err) == true);
        fct_chk(jw_dom_add_child(parent, children[4], &err) == true);

        childItr = jw_dom_get_first_child(parent);
        fct_chk(childItr == children[0]);
        childItr = jw_dom_get_sibling(childItr);
        fct_chk(childItr == children[1]);
        childItr = jw_dom_get_sibling(childItr);
        fct_chk(childItr == children[2]);
        childItr = jw_dom_get_sibling(childItr);
        fct_chk(childItr == children[3]);
        childItr = jw_dom_get_sibling(childItr);
        fct_chk(childItr == children[4]);
        childItr = jw_dom_get_sibling(childItr);
        fct_chk(childItr == NULL);

        fct_chk_eq_str(jw_dom_get_first_text(parent), "hello there, ");

        childItr = jw_dom_get_first_element(parent, NULL);
        fct_chk(childItr == children[0]);
        childItr = jw_dom_get_first_element(parent,
                                            "{http://www.w3.org/1999/xhtml}b");
        fct_chk(childItr == children[2]);
        childItr = jw_dom_get_first_element(parent,
                                            "{http://www.w3.org/1999/xhtml}span");
        fct_chk(childItr == children[0]);
        childItr = jw_dom_get_first_element(parent,
                                            "{http://www.w3.org/1999/xhtml}div");
        fct_chk(childItr == NULL);

        /* remove child via detach */
        jw_dom_detach(children[2]);
        childItr = jw_dom_get_first_child(parent);
        fct_chk(childItr == children[0]);
        childItr = jw_dom_get_sibling(childItr);
        fct_chk(childItr == children[1]);
        childItr = jw_dom_get_sibling(childItr);
        fct_chk(childItr == children[3]);
        childItr = jw_dom_get_sibling(childItr);
        fct_chk(childItr == children[4]);
        childItr = jw_dom_get_sibling(childItr);
        fct_chk(childItr == NULL);

        fct_chk_eq_str(jw_dom_get_first_text(parent), "hello there, ");

        childItr = jw_dom_get_first_element(parent, NULL);
        fct_chk(childItr == children[0]);
        childItr = jw_dom_get_first_element(parent,
                                            "{http://www.w3.org/1999/xhtml}b");
        fct_chk(childItr == NULL);
        childItr = jw_dom_get_first_element(parent,
                                            "{http://www.w3.org/1999/xhtml}span");
        fct_chk(childItr == children[0]);
        childItr = jw_dom_get_first_element(parent,
                                            "{http://www.w3.org/1999/xhtml}div");
        fct_chk(childItr == NULL);

        /* remove child via lookup */
        fct_chk(jw_dom_remove_child(parent,
                                    children[3],
                                    &err) == true);
        childItr = jw_dom_get_first_child(parent);
        fct_chk(childItr == children[0]);
        childItr = jw_dom_get_sibling(childItr);
        fct_chk(childItr == children[1]);
        childItr = jw_dom_get_sibling(childItr);
        fct_chk(childItr == children[4]);
        childItr = jw_dom_get_sibling(childItr);
        fct_chk(childItr == NULL);

        fct_chk_eq_str(jw_dom_get_first_text(parent), "hello there, ");

        childItr = jw_dom_get_first_element(parent, NULL);
        fct_chk(childItr == children[0]);
        childItr = jw_dom_get_first_element(parent,
                                            "{http://www.w3.org/1999/xhtml}b");
        fct_chk(childItr == NULL);
        childItr = jw_dom_get_first_element(parent,
                                            "{http://www.w3.org/1999/xhtml}span");
        fct_chk(childItr == children[0]);
        childItr = jw_dom_get_first_element(parent,
                                            "{http://www.w3.org/1999/xhtml}div");
        fct_chk(childItr == NULL);

        /* remove last */
        fct_chk(jw_dom_remove_child(parent,
                                    children[4],
                                    &err) == true);
        childItr = jw_dom_get_first_child(parent);
        fct_chk(childItr == children[0]);
        childItr = jw_dom_get_sibling(childItr);
        fct_chk(childItr == children[1]);
        childItr = jw_dom_get_sibling(childItr);
        fct_chk(childItr == NULL);

        fct_chk_eq_str(jw_dom_get_first_text(parent), "hello there, ");

        childItr = jw_dom_get_first_element(parent, NULL);
        fct_chk(childItr == children[0]);
        childItr = jw_dom_get_first_element(parent,
                                            "{http://www.w3.org/1999/xhtml}b");
        fct_chk(childItr == NULL);
        childItr = jw_dom_get_first_element(parent,
                                            "{http://www.w3.org/1999/xhtml}span");
        fct_chk(childItr == children[0]);
        childItr = jw_dom_get_first_element(parent,
                                            "{http://www.w3.org/1999/xhtml}div");
        fct_chk(childItr == NULL);

        /* remove first */
        fct_chk(jw_dom_remove_child(parent,
                                    children[0],
                                    &err) == true);
        childItr = jw_dom_get_first_child(parent);
        fct_chk(childItr == children[1]);
        childItr = jw_dom_get_sibling(childItr);
        fct_chk(childItr == NULL);

        fct_chk_eq_str(jw_dom_get_first_text(parent), "hello there, ");

        childItr = jw_dom_get_first_element(parent, NULL);
        fct_chk(childItr == NULL);
        childItr = jw_dom_get_first_element(parent,
                                            "{http://www.w3.org/1999/xhtml}b");
        fct_chk(childItr == NULL);
        childItr = jw_dom_get_first_element(parent,
                                            "{http://www.w3.org/1999/xhtml}span");
        fct_chk(childItr == NULL);
        childItr = jw_dom_get_first_element(parent,
                                            "{http://www.w3.org/1999/xhtml}div");
        fct_chk(childItr == NULL);
    } FCT_TEST_END()

    FCT_TEST_BGN(jw_dom_children_clear)
    {
        jw_dom_node     *parent;
        jw_dom_node     *children[5];
        jw_err          err;
        int             idx;

        fct_req(jw_dom_element_create(g_ctx,
                                      "{http://www.w3.org/1999/xhtml}div",
                                      &parent,
                                      &err) == true);
        fct_req(jw_dom_element_create(g_ctx,
                                      "{http://www.w3.org/1999/xhtml}span",
                                      &children[0],
                                      &err) == true);
        fct_req(jw_dom_text_create(g_ctx,
                                   "hello there, ",
                                   &children[1],
                                   &err) == true);
        fct_req(jw_dom_element_create(g_ctx,
                                      "{http://www.w3.org/1999/xhtml}b",
                                      &children[2],
                                      &err) == true);
        fct_req(jw_dom_element_create(g_ctx,
                                      "{http://www.w3.org/1999/xhtml}span",
                                      &children[3],
                                      &err) == true);
        fct_req(jw_dom_text_create(g_ctx,
                                   "foo!",
                                   &children[4],
                                   &err) == true);

        for (idx = 0; idx < 5; idx++)
        {
            fct_req(jw_dom_add_child(parent, children[idx], &err) == true);
        }

        jw_dom_clear_children(parent);
        fct_chk(jw_dom_get_first_child(parent) == NULL);
        for (idx = 0; idx < 5; idx++)
        {
            fct_chk(jw_dom_get_parent(children[idx]) == NULL);
        }
    } FCT_TEST_END()

    FCT_TEST_BGN(jw_dom_import)
    {
        jw_dom_ctx      *dupCtx;
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

            child = gchild;
            fct_req(jw_dom_text_create(g_ctx,
                                       "wherefore art thou, ",
                                       &gchild,
                                       &err) == true);
            fct_req(jw_dom_add_child(child, gchild, &err) == true);

            fct_req(jw_dom_element_create(g_ctx,
                                          "{http://www.w3.org/1999/xhtml}strong",
                                          &gchild,
                                          &err) == true);
            fct_req(jw_dom_set_attribute(gchild,
                                         "{}style",
                                         "color: blue",
                                         &err) == true);
            fct_req(jw_dom_add_child(child, gchild, &err) == true);

            child = gchild;
            fct_req(jw_dom_text_create(g_ctx,
                                       "romeo",
                                       &gchild,
                                       &err) == true);
            fct_req(jw_dom_add_child(child, gchild, &err) == true);

            child = jw_dom_get_parent(child);
            fct_req(jw_dom_text_create(g_ctx,
                                       "!",
                                       &gchild,
                                       &err) == true);
            fct_req(jw_dom_add_child(child, gchild, &err) == true);
        }

        /* check same context (no clone) */
        fct_chk(jw_dom_import(g_ctx, orig, false, &dup, &err) == true);
        fct_chk(orig == dup);
        fct_chk(jw_dom_import(g_ctx, orig, true, &dup, &err) == true);
        fct_chk(orig == dup);

        /* check shallow copy */
        fct_req(jw_dom_context_create(&dupCtx, &err) == true);
        fct_chk(jw_dom_import(dupCtx, orig, false, &dup, &err) == true);
        fct_chk(_domsEqual(dupCtx, orig, dup, false));
        jw_dom_context_destroy(dupCtx);

        /* check deep copy */
        fct_req(jw_dom_context_create(&dupCtx, &err) == true);
        fct_chk(jw_dom_import(dupCtx, orig, true, &dup, &err) == true);
        fct_chk(_domsEqual(dupCtx, orig, dup, true));
        jw_dom_context_destroy(dupCtx);

        /* check out of memory error */
       /* fct_req(jw_dom_context_create(&dupCtx, &err) == true);
        jw_data_set_memory_funcs(_malloc_fail, _realloc_fail, _free_noop);
        fct_chk(jw_dom_import(dupCtx, orig, false, &cpy, &err) == false);
        fct_chk_eq_int(err.code, JW_ERR_NO_MEMORY);
        fct_chk(jw_dom_import(dupCtx, orig, true, &cpy, &err) == false);
        fct_chk_eq_int(err.code, JW_ERR_NO_MEMORY);
        jw_dom_context_destroy(dupCtx);
        jw_data_set_memory_funcs(NULL, NULL, NULL);

        jw_dom_context_destroy(dupCtx);*/
    } FCT_TEST_END()
    FCT_TEST_BGN(jw_dom_clone)
    {
        jw_dom_ctx      *ictx;
        jw_dom_node     *orig, *dup, *iport, *idup;
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

            child = gchild;
            fct_req(jw_dom_text_create(g_ctx,
                                       "wherefore art thou, ",
                                       &gchild,
                                       &err) == true);
            fct_req(jw_dom_add_child(child, gchild, &err) == true);

            fct_req(jw_dom_element_create(g_ctx,
                                          "{http://www.w3.org/1999/xhtml}strong",
                                          &gchild,
                                          &err) == true);
            fct_req(jw_dom_set_attribute(gchild,
                                         "{}style",
                                         "color: blue",
                                         &err) == true);
            fct_req(jw_dom_add_child(child, gchild, &err) == true);

            child = gchild;
            fct_req(jw_dom_text_create(g_ctx,
                                       "romeo",
                                       &gchild,
                                       &err) == true);
            fct_req(jw_dom_add_child(child, gchild, &err) == true);

            child = jw_dom_get_parent(child);
            fct_req(jw_dom_text_create(g_ctx,
                                       "!",
                                       &gchild,
                                       &err) == true);
            fct_req(jw_dom_add_child(child, gchild, &err) == true);
        }

        /* check shallow copy */
        fct_chk(jw_dom_clone(orig, false, &dup, &err) == true);
        fct_chk(_domsEqual(g_ctx, orig, dup, false));

        /* check deep copy */
        fct_chk(jw_dom_clone(orig, true, &dup, &err) == true);
        fct_chk(_domsEqual(g_ctx, orig, dup, true));

        /* combined imports and clones */
        fct_req(jw_dom_context_create(&ictx, &err) == true);
        fct_chk(jw_dom_import(ictx, orig, true, &iport, &err));
        fct_chk(_domsEqual(ictx, orig, iport, true));
        fct_chk(jw_dom_clone(iport, true, &idup, &err));
        fct_chk(_domsEqual(ictx, iport, idup, true));
        fct_chk(_domsEqual(ictx, dup, idup, true));
        jw_dom_context_destroy(ictx);
    } FCT_TEST_END()

    FCT_TEST_BGN(jw_dom_int)
    {
        jw_dom_node *root, *intRoot;

        {
            jw_dom_node *child, *intChild, *gchild, *intGchild;

            fct_req(jw_dom_element_create(g_ctx,
                                          "{jabber:client}message",
                                          &root, NULL) == true);
            fct_req(jw_dom_element_create_int(g_ctx,
                                          "{jabber:client}message",
                                          &intRoot, NULL) == true);
            fct_req(jw_dom_put_namespace(root,
                                         "",
                                         "jabber:client", NULL) == true);
            fct_req(jw_dom_put_namespace_int(intRoot,
                                         "",
                                         "jabber:client", NULL) == true);
            fct_req(jw_dom_set_attribute(root,
                                         "{}from",
                                         "juliet@capulet.net/balcony",
                                         NULL) == true);
            fct_req(jw_dom_set_attribute_int(intRoot,
                                         "{}from",
                                         "juliet@capulet.net/balcony",
                                         NULL) == true);

            fct_req(jw_dom_element_create(g_ctx,
                                          "{jabber:client}thread",
                                          &child, NULL) == true);
            fct_req(jw_dom_element_create_int(g_ctx,
                                          "{jabber:client}thread",
                                          &intChild, NULL) == true);
            fct_req(jw_dom_add_child(root, child, NULL) == true);
            fct_req(jw_dom_add_child(intRoot, intChild, NULL) == true);
            fct_req(jw_dom_text_create(g_ctx,
                                       "some-random-guid",
                                       &gchild, NULL) == true);
            fct_req(jw_dom_text_create_int(g_ctx,
                                       "some-random-guid",
                                       &intGchild, NULL) == true);
            fct_req(jw_dom_add_child(child, gchild, NULL) == true);
            fct_req(jw_dom_add_child(intChild, intGchild, NULL) == true);
        }

        /* check that trees match */
        fct_chk(_domsEqual(g_ctx, root, intRoot, true));
    } FCT_TEST_END()

// TODO: currently fails due to de2808
//    FCT_TEST_BGN(jw_dom_add_vs_parse)
//    {
//        jw_dom_node     *parsed_node;
//        const char      *xmlExp = NULL;
//        struct evbuffer *inbuff = evbuffer_new();
//
//        xmlExp = "<presence xmlns='jabber:client'>"
//                   "<echosrv-command xmlns='http://cisco.com/echosrv'>"
//                     "<cmd xmlns=''>send</cmd>"
//                     "<error xmlns='jabber:client'>error text</error>"
//                   "</echosrv-command>"
//                 "</presence>";
//        fct_req(0 == evbuffer_add(inbuff, xmlExp, strlen(xmlExp)));
//        fct_req(jw_parse_xml_buffer(inbuff, &parsed_node, NULL));
//
//        jw_dom_ctx  *ctx;
//        jw_dom_node *presence, *errnode, *errtext;
//        jw_dom_node *cmdparent, *cmdchild, *cmdtext;
//
//        jw_dom_context_create(&ctx, NULL);
//        jw_dom_element_create(ctx, "{jabber:client}presence", &presence, NULL);
//        jw_dom_element_create(ctx, "{http://cisco.com/echosrv}echosrv-command",
//                              &cmdparent, NULL);
//        jw_dom_element_create(ctx, "{}cmd", &cmdchild, NULL);
//        jw_dom_text_create(ctx, "send", &cmdtext, NULL);
//        jw_dom_element_create(ctx, "{jabber:client}error", &errnode, NULL);
//        jw_dom_text_create(ctx, "error text", &errtext, NULL);
//        jw_dom_add_child(cmdchild, cmdtext, NULL);
//        jw_dom_add_child(cmdparent, cmdchild, NULL);
//        jw_dom_add_child(errnode, errtext, NULL);
//        jw_dom_add_child(cmdparent, errnode, NULL);
//        jw_dom_add_child(presence, cmdparent, NULL);
//
//        jw_log_dom(JW_LOG_DEBUG, parsed_node, "parsed_node: ");
//        jw_log_dom(JW_LOG_DEBUG, presence,    "presence: ");
//        fct_chk(_dom_equal(parsed_node, presence, true));
//
//        evbuffer_free(inbuff);
//        jw_dom_context_destroy(jw_dom_get_context(parsed_node));
//        jw_dom_context_destroy(ctx);
//    } FCT_TEST_END()

    FCT_TEST_BGN(jw_dom_retain)
    {
        jw_dom_ctx *ctx;
        jw_err     err;

        // wrap memory functions to detect when the free occurs
        _mallocCalled = false;
        _freeCalled = false;
        jw_data_set_memory_funcs(_dom_test_malloc, _dom_test_realloc, _dom_test_free);

        fct_req(jw_dom_context_create(&ctx, &err));
        fct_chk(_mallocCalled);
        fct_chk(!_freeCalled);
        fct_chk(1 == jw_dom_context_get_refcount_DEBUG(ctx));
        fct_req(jw_dom_context_retain(ctx, &err));
        fct_chk(2 == jw_dom_context_get_refcount_DEBUG(ctx));
        jw_dom_context_destroy(ctx);
        fct_chk(!_freeCalled);
        fct_chk(1 == jw_dom_context_get_refcount_DEBUG(ctx));
        jw_dom_context_destroy(ctx);
        fct_chk(_freeCalled);

        // reset memory functions to defaults
        jw_data_set_memory_funcs(NULL, NULL, NULL);
    } FCT_TEST_END()
} FCTMF_FIXTURE_SUITE_END()

FCTMF_SUITE_BGN(dom_refcount_begin)
{
    FCT_TEST_BGN(jw_dom_contexts_all_free)
    {
        jw_dom_ctx *c1, *c2, *c3;
        fct_chk(jw_dom_contexts_are_all_free(NULL));
        fct_chk(jw_dom_context_create(&c1, NULL));
        fct_chk(jw_dom_context_create(&c2, NULL));
        fct_chk(jw_dom_context_create(&c3, NULL));

        jw_dom_context_destroy(c2);
        jw_dom_context_destroy(c1);
        jw_dom_context_destroy(c3);
        fct_chk(jw_dom_contexts_are_all_free(NULL));
    } FCT_TEST_END()
     FCT_TEST_BGN(jw_dom_contexts_retain_free)
    {
        jw_dom_ctx *ctx;
        jw_err     err;
        fct_chk(jw_dom_contexts_are_all_free(NULL));
        fct_chk(jw_dom_context_create(&ctx, NULL));

        fct_chk(1 == jw_dom_context_get_refcount_DEBUG(ctx));
        fct_req(jw_dom_context_retain(ctx, &err));
        fct_chk(2 == jw_dom_context_get_refcount_DEBUG(ctx));
        jw_dom_context_destroy(ctx);
        fct_chk(1 == jw_dom_context_get_refcount_DEBUG(ctx));
        jw_dom_context_destroy(ctx);
        fct_chk(jw_dom_contexts_are_all_free(NULL));
    } FCT_TEST_END()
} FCTMF_SUITE_END()

FCTMF_SUITE_BGN(dom_refcount_end)
{
    FCT_TEST_BGN(jw_dom_contexts_all_free)
    {
       fct_chk(jw_dom_contexts_are_all_free(NULL));
    } FCT_TEST_END()
} FCTMF_SUITE_END()
