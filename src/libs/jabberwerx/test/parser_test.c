/**
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

#include "test_utils.h"
#include <event2/buffer.h>

#include <jabberwerx/dom.h>
#include <jabberwerx/util/str.h>
#include <jabberwerx/util/mem.h>
#include <jabberwerx/util/parser.h>
#include <jabberwerx/util/serializer.h>

#include <fct.h>


typedef enum {
    /** Root closing tag has been parsed*/
    JW_PARSER_CLOSED = 0,
    /** Root open tag has been parsed and is held "open" */
    JW_PARSER_OPEN = 1,
    /** A first level child of root has been parsed */
    JW_PARSER_ELEMENT = 2
} jw_parser_event_type;

static const char* ITR_ERROR_EXTRA = " extras ";
static const char* ITR_ERROR_MISSING = " missing ";

static jw_parser_event_type _lastEventType;
static jw_dom_node *_lastEventNode;
static size_t _lastUserData;

static bool _eqNode(jw_dom_node *actual, jw_dom_node *expected, char **buff, size_t *bufflen);

/* return a simple node name bread crumb, "parent>child>gchild>...>node"
   reallocs buff and adjust bufflen
   add title to front */
static void _addNodePath(jw_dom_node *node, char **buff, size_t *bufflen)
{
    char *name, *lbuff;
    size_t nlen, bpos;
    jw_dom_node *parent;

    if (node)
    {
        parent = jw_dom_get_parent(node);
        if (parent)
        {
            _addNodePath(parent, buff, bufflen);
        }
        if (jw_dom_get_nodetype(node) == JW_DOM_TYPE_ELEMENT)
        {
            name = (char *)(strrchr(jw_dom_get_ename(node), '}') + 1);
            nlen = jw_strlen(name);
            if (nlen)
            {
                bpos = *bufflen;
                *bufflen += (nlen + (nlen ? 1 : 0)); /* '>' if name exists */
                lbuff = *buff = (*buff == NULL ? malloc(*bufflen) :  realloc(*buff, *bufflen));
                memcpy(lbuff + bpos, name, nlen);
                *(lbuff + bpos + nlen) = '>';
            }
        }
    }
}
static void _addError(jw_dom_node *node, const char *error, char **buff, size_t *bufflen)
{
    char *lbuff;
    size_t elen;

    _addNodePath(node, buff, bufflen);

    elen = jw_strlen(error);
    lbuff = *buff = realloc(*buff, *bufflen + elen + 1);
    memcpy(lbuff + *bufflen, error, elen + 1); /*inc null*/
    *bufflen += (elen + 1);
}

static bool _eqIter(jw_dom_node *parent, const char* title, jw_dom_node *a_itr, jw_dom_node *e_itr, char **buff, size_t *bufflen)
{
    bool ret;
    size_t tlen, plen, bpos;
    const char *ename, *prefix;
    char *lbuff;
    jw_dom_node *itr;

    ret = true;
    while (a_itr && e_itr && ret)
    {
        ret = _eqNode(a_itr, e_itr, buff, bufflen);
        a_itr = jw_dom_get_sibling(a_itr);
        e_itr = jw_dom_get_sibling(e_itr);
    }

    itr = a_itr ? a_itr : e_itr;
    if (ret && itr) /* iterator count is different */
    {
       ret = false;
        _addNodePath(parent, buff, bufflen);
        /* additional actual nodes = "extra", additional expected = "missing"*/
        prefix = a_itr ? ITR_ERROR_EXTRA : ITR_ERROR_MISSING;
        plen = strlen(prefix);
        tlen = jw_strlen(title);
        bpos = *bufflen;
        *bufflen += plen + tlen + 1; /*alloc null here, add at end */
        lbuff = *buff = realloc(*buff, *bufflen);

        memcpy(lbuff + bpos, title, tlen);
        memcpy(lbuff + (bpos += tlen), prefix, plen);
        bpos += plen;

        /* list of "bad" nodes */
        for (; itr; itr = jw_dom_get_sibling(itr))
        {
            ename = jw_dom_get_ename(itr);
            tlen = jw_strlen(ename);
            *bufflen += tlen + 2;
            lbuff = *buff = realloc(*buff, *bufflen);

            *(lbuff + bpos) = '[';
            memcpy(lbuff + (++bpos), ename, tlen);
            *(lbuff + (bpos += tlen)) =  ']';
            ++bpos; /*loop expects pos ptr to be on byte to write*/
        }
        *(lbuff + bpos) = '\0';
    }
    return ret;
}
static bool _eqProp(jw_dom_node *node,
                    const char *propname,
                    const char *actual,
                    const char *expected,
                    char **buff, size_t *bufflen)
{
    size_t tlen, alen, elen, bpos;
    char *lbuff;

    if (jw_strcmp(actual, expected) == 0)
    {
        return true;
    }
    _addNodePath(node, buff, bufflen);

    tlen = jw_strlen(propname);
    alen = jw_strlen(actual);
    elen = jw_strlen(expected);
    bpos = *bufflen;
    *bufflen += tlen + alen + elen + 38; /* text + null */

    lbuff = *buff = realloc(*buff, *bufflen);
    memcpy(lbuff + bpos, propname, tlen);
    /* hardcoded constants but meh, doubt these formats will change */
    memcpy(lbuff + (bpos += tlen), " does not match, expected '", 27);
    memcpy(lbuff + (bpos += 27), expected, elen);
    memcpy(lbuff + (bpos += elen), "' found '", 9);
    memcpy(lbuff + (bpos += 9), actual, alen);
    memcpy(lbuff + (bpos += alen), "'", 2);
    return false;
}
static bool _eqNode(jw_dom_node *actual, jw_dom_node *expected, char **buff, size_t *bufflen)
{
    bool ret;

    if (expected == actual)
    {
        return true;
    }
    if (expected == NULL)
    {
        _addError(actual, "NULL check does not match, expected NULL", buff, bufflen);
        return false;
    }
    if (actual == NULL)
    {
        _addError(NULL, "NULL check does not match, expected non-NULL", buff, bufflen);
        return false;
    }
    if (jw_dom_get_nodetype(actual) != jw_dom_get_nodetype(expected))
    {
        _addError(actual, "Types do not match", buff, bufflen);
        return false;
    }

    ret = _eqProp(actual, "ename",
                  jw_dom_get_ename(actual), jw_dom_get_ename(expected),
                  buff, bufflen)
          && _eqProp(actual, "value",
                     jw_dom_get_value(actual), jw_dom_get_value(expected),
                     buff, bufflen)
          && ((jw_dom_get_nodetype(actual) != JW_DOM_TYPE_ELEMENT)
              || (_eqIter(actual, "nss",
                             jw_dom_get_first_namespace(actual),
                             jw_dom_get_first_namespace(expected),
                             buff, bufflen)
                  && _eqIter(actual, "attrs",
                             jw_dom_get_first_attribute(actual),
                             jw_dom_get_first_attribute(expected),
                             buff, bufflen)
                  && _eqIter(actual, "children",
                             jw_dom_get_first_child(actual),
                             jw_dom_get_first_child(expected),
                             buff, bufflen)));
    return ret;
}
static bool _eq_node(jw_pool *pool, jw_dom_node *actual, jw_dom_node *expected, char **buff, size_t *bufflen)
{
    char *lbuff;
    size_t lbufflen;

    lbuff = NULL;
    lbufflen = 0;
    if (!_eqNode(actual, expected, &lbuff, &lbufflen))
    {
        *buff = lbuff;
        *bufflen = lbufflen;
        if (pool)
        {
            jw_pool_add_cleaner(pool, (jw_pool_cleaner)free, lbuff, NULL);
        }
        return false;
    }
    return true;
}

/* test fragments */
static const char *str_stream_open =
"<stream:stream from='example.com' "
                "id='someid' "
                "xmlns='jabber:client' "
                "xmlns:stream='http://etherx.jabber.org/streams' "
                "version='1.0'>";
static jw_dom_node *node_stream_open()
{
    jw_dom_node *ret;
    jw_dom_ctx *ctx;

    jw_dom_context_create(&ctx, NULL);
    jw_dom_element_create(ctx, "{http://etherx.jabber.org/streams}stream", &ret, NULL);
    jw_dom_put_namespace(ret, "", "jabber:client", NULL);
    jw_dom_put_namespace(ret, "stream", "http://etherx.jabber.org/streams", NULL);
    jw_dom_set_attribute(ret, "{}from", "example.com", NULL);
    jw_dom_set_attribute(ret, "{}id", "someid", NULL);
    jw_dom_set_attribute(ret, "{}version", "1.0", NULL);
    return ret;
}

static const char *str_stream_error =
"<stream:error xmlns:stream='http://etherx.jabber.org/streams'>"
    "<xml-not-well-formed xmlns='urn:ietf:params:xml:ns:xmpp-streams'/>"
"</stream:error>";
static jw_dom_node *node_stream_error()
{
    jw_dom_node *ret, *child;
    jw_dom_ctx *ctx;

    jw_dom_context_create(&ctx, NULL);
    jw_dom_element_create(ctx, "{http://etherx.jabber.org/streams}error", &ret, NULL);
    jw_dom_put_namespace(ret, "stream", "http://etherx.jabber.org/streams", NULL);
    jw_dom_element_create(ctx, "{urn:ietf:params:xml:ns:xmpp-streams}xml-not-well-formed", &child, NULL);
    jw_dom_put_namespace(child, "", "urn:ietf:params:xml:ns:xmpp-streams", NULL);
    jw_dom_add_child(ret, child, NULL);
    return ret;
}
static const char *str_stream_close = "</stream:stream>";

static const char *str_simple_message =
"<message xmlns='jabber:client' "
    "xml:lang='en'>"
    "<body>Hi there</body>"
"</message>";
static jw_dom_node *node_simple_message()
{
    jw_dom_node *result, *tn, *tn2;
    jw_dom_ctx *context;
    jw_dom_context_create(&context, NULL);
    jw_dom_element_create(context, "{jabber:client}message", &result, NULL);
    jw_dom_put_namespace(result, "", "jabber:client", NULL);
    jw_dom_set_attribute(result, "{http://www.w3.org/XML/1998/namespace}lang", "en", NULL);
    jw_dom_element_create(context, "{jabber:client}body", &tn, NULL);
    jw_dom_add_child(result, tn, NULL);
    jw_dom_text_create(context, "Hi there", &tn2, NULL);
    jw_dom_add_child(tn, tn2, NULL);
    return result;
}

static const char *str_thanks_matt =
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
static jw_dom_node *node_thanks_matt()
{
    jw_dom_node *child, *gchild, *orig;
    jw_dom_ctx *g_ctx;

    jw_dom_context_create(&g_ctx, NULL);
    jw_dom_element_create(g_ctx, "{jabber:client}message", &orig, NULL);
    jw_dom_put_namespace(orig, "","jabber:client", NULL);
    jw_dom_set_attribute(orig, "{}from", "juliet@capulet.net/balcony", NULL);
    jw_dom_set_attribute(orig, "{}id", "some-random-message-id", NULL);
    jw_dom_set_attribute(orig, "{}to", "romeo@montegue.net",NULL);
    jw_dom_set_attribute(orig, "{}type", "chat", NULL);

    jw_dom_element_create(g_ctx, "{jabber:client}thread", &child, NULL);
    jw_dom_add_child(orig, child, NULL);
    jw_dom_text_create(g_ctx, "some-random-guid", &gchild, NULL);
    jw_dom_add_child(child, gchild, NULL);

    jw_dom_element_create(g_ctx, "{jabber:client}body", &child, NULL);
    jw_dom_add_child(orig, child, NULL);
    jw_dom_text_create(g_ctx, "wherefore art thou, romeo!", &gchild, NULL);
    jw_dom_add_child(child, gchild, NULL);

    jw_dom_element_create(g_ctx, "{http://jabber.org/protocol/chatstates}active", &child, NULL);
    jw_dom_put_namespace(child, "", "http://jabber.org/protocol/chatstates", NULL);
    jw_dom_add_child(orig, child, NULL);

    jw_dom_element_create(g_ctx, "{http://jabber.org/protocol/xhtml-im}html", &child, NULL);
    jw_dom_put_namespace(child, "", "http://jabber.org/protocol/xhtml-im", NULL);
    jw_dom_add_child(orig, child, NULL);
    jw_dom_element_create(g_ctx, "{http://www.w3.org/1999/xhtml}body", &gchild, NULL);
    jw_dom_put_namespace(gchild, "", "http://www.w3.org/1999/xhtml", NULL);
    jw_dom_add_child(child, gchild, NULL);

    child = gchild;
    jw_dom_element_create(g_ctx, "{http://www.w3.org/1999/xhtml}p", &gchild, NULL);
    jw_dom_add_child(child, gchild, NULL);

    child = gchild;
    jw_dom_text_create(g_ctx, "wherefore art thou, ", &gchild, NULL);
    jw_dom_add_child(child, gchild, NULL);

    jw_dom_element_create(g_ctx, "{http://www.w3.org/1999/xhtml}strong", &gchild, NULL);
    jw_dom_set_attribute(gchild, "{}style", "color: blue", NULL);
    jw_dom_add_child(child, gchild, NULL);

    child = gchild;
    jw_dom_text_create(g_ctx, "romeo", &gchild, NULL);
    jw_dom_add_child(child, gchild, NULL);

    child = jw_dom_get_parent(child);
    jw_dom_text_create(g_ctx, "!", &gchild, NULL);
    jw_dom_add_child(child, gchild, NULL);
    return orig;
}

static const char *str_bad_xml_malformed = "<foo bar=baz/>";
static const char *str_bad_xml_noclose = "<foo>bad xml";
static const char *str_bad_xml_multiple = "<foo/><bar/>";
static const char *str_bad_xml_unknown_ent = "<foo>&myent;</foo>";
static const char *str_bad_xml_dtd = "<!DOCTYPE test SYSTEM 'test.dtd'><test>This shouldn't be parsed</test>";

static const char *str_xml_entities =
"<foo xmlns='jabber:client' attr1='&lt;&amp;&quot;&apos;&gt;'>"
    "&lt;&amp;&quot;&#60;&#62;"
    "<bar>bar text</bar>"
    "&apos;&gt;01234567890"
"</foo>";
static jw_dom_node *node_xml_entities()
{
    jw_dom_node *child, *gchild, *result;
    jw_dom_ctx *g_ctx;

    jw_dom_context_create(&g_ctx, NULL);
    jw_dom_element_create(g_ctx, "{jabber:client}foo", &result, NULL);
    jw_dom_put_namespace(result, "", "jabber:client", NULL);
    jw_dom_text_create(g_ctx, "<&\"<>", &child, NULL);
    jw_dom_add_child(result, child, NULL);
    jw_dom_element_create(g_ctx, "{jabber:client}bar", &child, NULL);
    jw_dom_add_child(result, child, NULL);
    jw_dom_text_create(g_ctx, "bar text", &gchild, NULL);
    jw_dom_add_child(child, gchild, NULL);
    jw_dom_text_create(g_ctx, "'>01234567890", &child, NULL);
    jw_dom_add_child(result, child, NULL);
    jw_dom_set_attribute(result, "{}attr1", "<&\"'>", NULL);
    return result;
}

static const char *str_iq_command_result =
"<iq from='joogle@botster.shakespeare.lit' type='result' xml:lang='en' id='create1'>"
    "<command xmlns='http://jabber.org/protocol/commands' node='create' sessionid='create:20040408T0128Z' status='executing'>"
        "<x xmlns='jabber:x:data' type='form'>"
            "<title>Bot Configuration</title>"
            "<instructions>Fill out this form to configure your new bot!</instructions>"
            "<field type='hidden' var='FORM_TYPE'><value>jabber:bot</value></field>"
            "<field type='fixed'><value>Section 1: Bot Info</value></field>"
            "<field type='text-single' label='The name of your bot' var='botname'/>"
            "<field type='text-multi' label='Helpful description of your bot' var='description'/>"
            "<field type='boolean' label='Public bot?' var='public'><required/></field>"
            "<field type='text-private' label='Password for special access' var='password'/>"
            "<field type='fixed'><value>Section 2: Features</value></field>"
            "<field type='list-multi' label='What features will the bot support?' var='features'>"
                "<option label='Contests'><value>contests</value></option>"
                "<option label='News'><value>news</value></option>"
                "<option label='Polls'><value>polls</value></option>"
                "<option label='Reminders'><value>reminders</value></option>"
                "<option label='Search'><value>search</value></option>"
                "<value>news</value>"
                "<value>search</value>"
            "</field>"
            "<field type='fixed'><value>Section 3: Subscriber List</value></field>"
            "<field type='list-single' label='Maximum number of subscribers' var='maxsubs'>"
                "<value>20</value>"
                "<option label='10'><value>10</value></option>"
                "<option label='20'><value>20</value></option>"
                "<option label='30'><value>30</value></option>"
                "<option label='50'><value>50</value></option>"
                "<option label='100'><value>100</value></option>"
                "<option label='None'><value>none</value></option>"
            "</field>"
            "<field type='fixed'><value>Section 4: Invitations</value></field>"
            "<field type='jid-multi' label='People to invite' var='invitelist'>"
                "<desc>Tell all your friends about your new bot!</desc>"
            "</field>"
        "</x>"
    "</command>"
"</iq>";

static const char *str_namespaceless_xml = "<outer><inner>1234234</inner></outer>";
static jw_dom_node *node_namespaceless_xml()
{
    jw_dom_node *result, *tn, *tn2;
    jw_dom_ctx *context;
    jw_dom_context_create(&context, NULL);
    jw_dom_element_create(context, "{}outer", &result, NULL);
    jw_dom_element_create(context, "{}inner", &tn, NULL);
    jw_dom_add_child(result, tn, NULL);
    jw_dom_text_create(context, "1234234", &tn2, NULL);
    jw_dom_add_child(tn, tn2, NULL);
    return result;
}

static void parse_handler_open(jw_event_data evt, void *arg)
{
    _lastEventType = JW_PARSER_OPEN;
    _lastEventNode = (jw_dom_node*)evt->data;
    _lastUserData = *(size_t *)arg;
    if (!jw_dom_context_retain(jw_dom_get_context(_lastEventNode), NULL))
    {
        assert(false);
    }
    evt->handled = true;
}

static void parse_handler_element(jw_event_data evt, void *arg)
{
    _lastEventType = JW_PARSER_ELEMENT;
    _lastEventNode = (jw_dom_node*)evt->data;
    _lastUserData = *(size_t *)arg;
    if (!jw_dom_context_retain(jw_dom_get_context(_lastEventNode), NULL))
    {
        assert(false);
    }
    evt->handled = true;
}

static void parse_handler_closed(jw_event_data evt, void *arg)
{
    _lastEventType = JW_PARSER_CLOSED;
    _lastEventNode = (jw_dom_node*)evt->data;
    _lastUserData = *(size_t *)arg;
}

static void testReset(char **errStr, size_t *errLen)
{
    _lastEventNode = NULL;
    _lastEventType = JW_PARSER_CLOSED;
    _lastUserData = 0;
    *errStr = NULL;
    *errLen = 0;
}

static void root_handler_open(jw_event_data evt, void *arg)
{
    jw_dom_node **root = (jw_dom_node **)arg;
    *root = (jw_dom_node*)evt->data;
    if (!jw_dom_context_retain(jw_dom_get_context(*root), NULL))
    {
        assert(false);
    }
    evt->handled = true;
}

static void root_handler_element(jw_event_data evt, void *arg)
{
    jw_dom_node *element = (jw_dom_node*)evt->data;
    jw_dom_node *inode, **root = (jw_dom_node **)arg;
    jw_dom_import(jw_dom_get_context(*root), element, true, &inode, NULL);
    jw_dom_add_child(*root, inode, NULL);
    evt->handled = true;
}

static bool _parser_oom_test(jw_err *err)
{
    struct evbuffer *buf = NULL;
    jw_parser  *xs  = NULL;

    bool ret = false;

    if (!(buf = evbuffer_new())
     || 0 != evbuffer_add_reference(
                buf, str_thanks_matt, strlen(str_thanks_matt), NULL, NULL)
     || !jw_parser_create(true, &xs, err)
     || !jw_parser_process(xs, buf, err))
    {
        goto _parser_oom_test_done_label;
    }

    ret = true;

_parser_oom_test_done_label:
    if (xs)
    {
        jw_parser_destroy(xs);
    }
    if (buf)
    {
        evbuffer_free(buf);
    }
    return ret;
}


static jw_loglevel _initlevel;
FCTMF_FIXTURE_SUITE_BGN(parser_test)
{
    FCT_SETUP_BGN()
    {
        _initlevel = jw_log_get_level();
        _test_init_counting_memory_funcs();
    } FCT_SETUP_END()

    FCT_TEARDOWN_BGN()
    {
        fct_chk_eq_int(_test_get_free_count(), _test_get_malloc_count());
        if (_test_get_free_count() != _test_get_malloc_count())
        {
            jw_log(JW_LOG_ERROR,
                   "mem leak detected in %s: %u allocations, %u frees",
                   fctkern_ptr__->ns.curr_test_name,
                   _test_get_malloc_count(), _test_get_free_count());
        }
        _test_uninit_counting_memory_funcs();
        jw_log_set_level(_initlevel);
    } FCT_TEARDOWN_END()

    FCT_TEST_BGN(jw_parser_create_destroy)
    {
        jw_parser *xs;
        jw_err err;

        fct_chk(jw_parser_create(true,
                                 &xs,
                                 &err));
        fct_chk(xs);
        jw_parser_destroy(xs);

    } FCT_TEST_END()

    FCT_TEST_BGN(jw_parser_stream_process)
    {
        jw_parser *xs;
        jw_dom_node *tn;
        jw_err err;
        jw_pool *errPool;
        char *errStr;
        size_t errLen;
        size_t myuserdata = 42;
        struct evbuffer *b2, *buffer = evbuffer_new();

        jw_pool_create(1024, &errPool, NULL);
        fct_req(jw_parser_create(true,
                                 &xs,
                                 &err));
        fct_req(xs);

        fct_chk(jw_event_bind(jw_parser_event(xs, JW_PARSER_EVENT_OPEN),
                              parse_handler_open,
                              &myuserdata,
                              &err));
        fct_chk(jw_event_bind(jw_parser_event(xs, JW_PARSER_EVENT_ELEMENT),
                              parse_handler_element,
                              &myuserdata,
                              &err));
        fct_chk(jw_event_bind(jw_parser_event(xs, JW_PARSER_EVENT_CLOSED),
                              parse_handler_closed,
                              &myuserdata,
                              &err));

        fct_chk(jw_parser_process(xs, NULL, &err)); //coverage

        testReset(&errStr, &errLen);
        evbuffer_add(buffer, str_stream_open, strlen(str_stream_open));
        fct_req(jw_parser_process(xs, buffer, &err));
        fct_chk(_lastEventType == JW_PARSER_OPEN);
        fct_chk(_lastEventNode != NULL);
        fct_chk_eq_int(_lastUserData, 42);
        tn = node_stream_open();
        fct_chk(_eq_node(errPool, _lastEventNode, tn, &errStr, &errLen));
        fct_chk_eq_str(errStr, NULL);
        fct_chk_eq_int(errLen, 0);
        fct_chk(evbuffer_get_length(buffer) == 0);
        jw_dom_context_destroy(jw_dom_get_context(tn));
        jw_dom_context_destroy(jw_dom_get_context(_lastEventNode));

        testReset(&errStr, &errLen);
        evbuffer_add_printf(buffer, "%s", str_simple_message);
        fct_req(jw_parser_process(xs, buffer, &err));
        fct_chk_eq_int(_lastEventType, JW_PARSER_ELEMENT);
        fct_chk(_lastEventNode != NULL);
        fct_chk_eq_int(_lastUserData, 42);
        tn = node_simple_message();
        fct_chk(_eq_node(errPool, _lastEventNode, tn, &errStr, &errLen));
        fct_chk_eq_str(errStr, NULL);
        fct_chk_eq_int(errLen, 0);
        fct_chk(evbuffer_get_length(buffer) == 0);
        jw_dom_context_destroy(jw_dom_get_context(tn));
        jw_dom_context_destroy(jw_dom_get_context(_lastEventNode));

        testReset(&errStr, &errLen);
        b2 = evbuffer_new();
        evbuffer_add_reference(b2, str_thanks_matt, strlen(str_thanks_matt), NULL, NULL);
        evbuffer_add_buffer(buffer, b2);
        fct_req(jw_parser_process(xs, buffer, &err));
        fct_chk(_lastEventType == JW_PARSER_ELEMENT);
        fct_chk(_lastEventNode != NULL);
        fct_chk_eq_int(_lastUserData, 42);
        tn = node_thanks_matt();
        fct_chk(_eq_node(errPool, _lastEventNode, tn, &errStr, &errLen));
        fct_chk_eq_str(errStr, NULL);
        fct_chk_eq_int(errLen, 0);
        fct_chk(evbuffer_get_length(buffer) == 0);
        evbuffer_free(b2);
        jw_dom_context_destroy(jw_dom_get_context(tn));
        jw_dom_context_destroy(jw_dom_get_context(_lastEventNode));

        testReset(&errStr, &errLen);
        evbuffer_add(buffer, str_iq_command_result, strlen(str_iq_command_result));
        fct_req(jw_parser_process(xs, buffer, &err));
        fct_chk(_lastEventType == JW_PARSER_ELEMENT);
        fct_chk(_lastEventNode != NULL);
        fct_chk_eq_int(_lastUserData, 42);
        fct_chk_eq_int(errLen, 0);
        fct_chk(evbuffer_get_length(buffer) == 0);
        jw_dom_context_destroy(jw_dom_get_context(_lastEventNode));

        testReset(&errStr, &errLen);
        evbuffer_add_reference(buffer, str_stream_error, strlen(str_stream_error), NULL, NULL);
        tn = node_stream_error();
        fct_req(jw_parser_process(xs, buffer, &err));
        fct_chk(_lastEventType == JW_PARSER_ELEMENT);
        fct_chk(_lastEventNode != NULL);
        fct_chk_eq_int(_lastUserData, 42);
        fct_chk(_eq_node(errPool, _lastEventNode, tn, &errStr, &errLen));
        fct_chk_eq_str(errStr, NULL);
        fct_chk_eq_int(errLen, 0);
        fct_chk(evbuffer_get_length(buffer) == 0);
        jw_dom_context_destroy(jw_dom_get_context(tn));
        jw_dom_context_destroy(jw_dom_get_context(_lastEventNode));

        testReset(&errStr, &errLen);
        tn = node_xml_entities();
        evbuffer_add(buffer, str_xml_entities, strlen(str_xml_entities));
        fct_req(jw_parser_process(xs, buffer, &err));
        fct_chk(_lastEventType == JW_PARSER_ELEMENT);
        fct_chk(_lastEventNode != NULL);
        fct_chk_eq_int(_lastUserData, 42);
        fct_chk(_eq_node(errPool, _lastEventNode, tn, &errStr, &errLen));
        fct_chk_eq_str(errStr, NULL);
        fct_chk_eq_int(errLen, 0);
        fct_chk(evbuffer_get_length(buffer) == 0);
        jw_dom_context_destroy(jw_dom_get_context(tn));
        jw_dom_context_destroy(jw_dom_get_context(_lastEventNode));

        testReset(&errStr, &errLen);
        evbuffer_add_reference(buffer, str_stream_close, strlen(str_stream_close), NULL, NULL);
        _lastEventType = JW_PARSER_OPEN;
        fct_req(jw_parser_process(xs, buffer, &err));
        fct_chk(_lastEventType == JW_PARSER_CLOSED);
        fct_chk(_lastEventNode == NULL);
        fct_chk_eq_int(_lastUserData, 42);
        fct_chk_eq_int(errLen, 0);
        fct_chk(evbuffer_get_length(buffer) == 0);

        evbuffer_free(buffer);
        jw_parser_destroy(xs);
        jw_pool_destroy(errPool);
    } FCT_TEST_END()

    FCT_TEST_BGN(jw_parser_root_text)
    {
        jw_parser *xs;
        jw_dom_node *tn, *pn;
        jw_err err;
        jw_pool *errPool;
        char *errStr = NULL;
        size_t errLen = 0;
        struct evbuffer *buffer = evbuffer_new();

        jw_pool_create(1024, &errPool, NULL);
        /* create a streaming parser, handler build pn dom for later compare */
        fct_req(jw_parser_create(true,
                                 &xs,
                                 &err));
        fct_req(xs);

        fct_chk(jw_event_bind(jw_parser_event(xs, JW_PARSER_EVENT_OPEN),
                              root_handler_open,
                              &pn,
                              &err));
        fct_chk(jw_event_bind(jw_parser_event(xs, JW_PARSER_EVENT_ELEMENT),
                              root_handler_element,
                              &pn,
                              &err));

        /* parse in the context of xml_entities root rather than stream */
        tn = node_xml_entities();
        evbuffer_add(buffer, str_xml_entities, strlen(str_xml_entities));
        fct_req(jw_parser_process(xs, buffer, &err));
        fct_chk(_eq_node(errPool, pn, tn, &errStr, &errLen));
        fct_chk_eq_str(errStr, NULL);
        fct_chk_eq_int(errLen, 0);
        jw_dom_context_destroy(jw_dom_get_context(tn));
        jw_dom_context_destroy(jw_dom_get_context(pn));
        evbuffer_free(buffer);
        jw_parser_destroy(xs);
        jw_pool_destroy(errPool);
    } FCT_TEST_END()

    FCT_TEST_BGN(jw_parser_process_bad_state)
    {
        jw_parser *xs;
        jw_err err;
        jw_pool *errPool;
        char *errStr;
        size_t errLen;
        size_t myuserdata = 42;
        struct evbuffer *buffer = evbuffer_new();

        jw_pool_create(1024, &errPool, NULL);
        fct_req(jw_parser_create(true,
                                 &xs,
                                 &err));
        fct_req(xs);

        fct_chk(jw_event_bind(jw_parser_event(xs, JW_PARSER_EVENT_OPEN),
                              parse_handler_open,
                              &myuserdata,
                              &err));
        fct_chk(jw_event_bind(jw_parser_event(xs, JW_PARSER_EVENT_ELEMENT),
                              parse_handler_element,
                              &myuserdata,
                              &err));
        fct_chk(jw_event_bind(jw_parser_event(xs, JW_PARSER_EVENT_CLOSED),
                              parse_handler_closed,
                              &myuserdata,
                              &err));

        testReset(&errStr, &errLen);
        evbuffer_add_reference(buffer, str_stream_open, strlen(str_stream_open), NULL, NULL);
        fct_req(jw_parser_process(xs, buffer, &err));
        fct_chk(evbuffer_get_length(buffer) == 0);
        jw_dom_context_destroy(jw_dom_get_context(_lastEventNode));

        evbuffer_add(buffer, str_bad_xml_malformed, strlen(str_bad_xml_malformed));
        fct_req(jw_parser_process(xs, buffer, &err) == false);
        fct_chk(err.code == JW_ERR_INVALID_ARG);

        evbuffer_add_printf(buffer, "%s", str_simple_message);
        fct_req(jw_parser_process(xs, buffer, &err) == false);
        fct_chk(err.code == JW_ERR_INVALID_STATE);

        evbuffer_free(buffer);
        jw_parser_destroy(xs);
        jw_pool_destroy(errPool);
    } FCT_TEST_END()

    FCT_TEST_BGN(jw_parse_xml)
    {
        jw_err err;
        jw_dom_node *node, *tn;
        jw_pool *errPool;
        char *errStr;
        size_t errLen;

        jw_pool_create(1024, &errPool, NULL);

        /* parsing fail tests */
        fct_req(jw_parse_xml(str_bad_xml_malformed, &node, &err) == false);
        fct_chk(err.code == JW_ERR_INVALID_ARG);
        fct_chk(jw_parse_xml(str_bad_xml_noclose, &node, &err) == false);
        fct_chk(jw_parse_xml(str_bad_xml_multiple, &node, &err) == false);
        fct_chk(jw_parse_xml(str_bad_xml_unknown_ent, &node, &err) == false);
        fct_chk(jw_parse_xml(str_bad_xml_dtd, &node, &err) == false);
        //coverage
        fct_req(jw_parse_xml(str_bad_xml_malformed, &node, NULL) == false);
        fct_chk(jw_parse_xml(str_bad_xml_noclose, &node, NULL) == false);
        fct_chk(jw_parse_xml(str_bad_xml_multiple, &node, NULL) == false);
        fct_chk(jw_parse_xml(str_bad_xml_unknown_ent, &node, NULL) == false);
        fct_chk(jw_parse_xml(str_bad_xml_dtd, &node, NULL) == false);

        errStr = NULL;
        errLen = 0;
        fct_req(jw_parse_xml(str_simple_message, &node, &err) == true);
        tn = node_simple_message();
        fct_chk(_eq_node(errPool, node, tn, &errStr, &errLen));
        fct_chk_eq_str(errStr, NULL);
        fct_chk_eq_int(errLen, 0);
        jw_dom_context_destroy(jw_dom_get_context(tn));
        jw_dom_context_destroy(jw_dom_get_context(node));

        node = NULL;
        fct_chk(jw_parse_xml("", &node, &err) && !node); //coverage 0 length

        errStr = NULL;
        errLen = 0;
        fct_req(jw_parse_xml(str_thanks_matt, &node, &err));
        tn = node_thanks_matt();
        fct_chk(_eq_node(errPool, node, tn, &errStr, &errLen));
        fct_chk_eq_str(errStr, NULL);
        fct_chk_eq_int(errLen, 0);
        jw_dom_context_destroy(jw_dom_get_context(tn));
        jw_dom_context_destroy(jw_dom_get_context(node));

        errStr = NULL;
        errLen = 0;
        fct_req(jw_parse_xml(str_xml_entities, &node, &err) == true);
        tn = node_xml_entities();
        fct_chk(_eq_node(errPool, node, tn, &errStr, &errLen));
        fct_chk_eq_str(errStr, NULL);
        fct_chk_eq_int(errLen, 0);
        jw_dom_context_destroy(jw_dom_get_context(tn));
        jw_dom_context_destroy(jw_dom_get_context(node));

        jw_pool_destroy(errPool);
    } FCT_TEST_END()

    FCT_TEST_BGN(jw_parse_xml_buffer)
    {
        jw_err err;
        jw_pool *errPool;
        char *errStr;
        size_t errLen;
        jw_dom_node *node, *tn, *pn;
        struct evbuffer *buffer = evbuffer_new();

        jw_pool_create(1024, &errPool, NULL);

        fct_chk(jw_parse_xml_buffer(buffer, &node, &err)); //o length buffer

        testReset(&errStr, &errLen);
        evbuffer_add(buffer, str_thanks_matt, strlen(str_thanks_matt));
        fct_req(jw_parse_xml_buffer(buffer, &node, &err) == true);
        tn = node_thanks_matt();
        fct_chk(_eq_node(errPool, node, tn, &errStr, &errLen));
        fct_chk_eq_str(errStr, NULL);
        fct_chk_eq_int(errLen, 0);
        jw_dom_context_destroy(jw_dom_get_context(node));
        jw_dom_context_destroy(jw_dom_get_context(tn));

        errStr = NULL;
        errLen = 0;
        evbuffer_add(buffer, str_bad_xml_malformed, strlen(str_bad_xml_malformed));
        fct_req(jw_parse_xml_buffer(buffer, &pn, &err) == false);
        fct_chk(err.code == JW_ERR_INVALID_ARG);

        evbuffer_free(buffer);
        jw_pool_destroy(errPool);
    } FCT_TEST_END()

    FCT_TEST_BGN(jw_parse_namespaceless_xml)
    {
        jw_err err;
        jw_dom_node *node, *child, *tn, *tn2;
        jw_pool *errPool;
        char *errStr;
        size_t errLen;

        jw_pool_create(1024, &errPool, NULL);

        errStr = NULL;
        errLen = 0;
        tn = node_namespaceless_xml();
        fct_req(jw_parse_xml(str_namespaceless_xml, &node, &err));
        fct_chk(_eq_node(errPool, node, tn, &errStr, &errLen));
        fct_chk_eq_str(errStr, NULL);
        fct_chk_eq_int(errLen, 0);
        fct_chk_eq_str("{}outer", jw_dom_get_ename(tn));
        fct_chk_eq_str("{}outer", jw_dom_get_ename(node));
        fct_chk_eq_str("outer", jw_dom_get_localname(tn));
        fct_chk_eq_str("outer", jw_dom_get_localname(node));
        tn2 = jw_dom_get_first_element(tn, NULL);
        child = jw_dom_get_first_element(node, NULL);
        fct_req(tn2);
        fct_req(child);
        fct_chk_eq_str("{}inner", jw_dom_get_ename(tn2));
        fct_chk_eq_str("{}inner", jw_dom_get_ename(child));
        fct_chk_eq_str("inner", jw_dom_get_localname(tn2));
        fct_chk_eq_str("inner", jw_dom_get_localname(child));
        jw_dom_context_destroy(jw_dom_get_context(tn));
        jw_dom_context_destroy(jw_dom_get_context(node));

        jw_pool_destroy(errPool);
    } FCT_TEST_END()

    FCT_TEST_BGN(jw_parser_oom)
    {
        //jw_log_set_level(JW_LOG_TRACE);

        jw_err err;

        OOM_RECORD_ALLOCS(_parser_oom_test(&err));
        OOM_TEST_INIT();
        OOM_TEST_NO_CHECK(&err, _parser_oom_test(&err));
        OOM_TEST_INIT();
        OOM_TEST_NO_CHECK(NULL, _parser_oom_test(NULL));
    } FCT_TEST_END()
} FCTMF_FIXTURE_SUITE_END()
