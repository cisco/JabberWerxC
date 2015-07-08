/**
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <expat.h>
#include <jabberwerx/util/parser.h>
#include <jabberwerx/util/str.h>
#include <jabberwerx/util/log.h>
#include "../include/dom_int.h"


typedef struct _ns_entry_t
{
    jw_pool *pool;
    char    *prefix;
    char    *uri;

    struct _ns_entry_t *next;
} *_ns_entry;

struct _jw_parser
{
    XML_Parser   parser;
    bool         opened;
    bool         streaming;
    jw_dom_node *parsing_node;
    char        *pnode_cdata;
    _ns_entry    namespaces;  // namespace queue head
    _ns_entry    ns_tail;     // namespace queue tail

    jw_event_dispatcher *dispatch;
    jw_event            *event_opened;
    jw_event            *event_closed;
    jw_event            *event_element;
    jw_err               error;
};

// ensure expat uses jwc's allocation functions for OOM testing, debugging etc.
// TODO: change this back to static const and update bosh_test.c once the
// TODO: memory leak in expat is sussed out.
XML_Memory_Handling_Suite _xmlMs = {
    .malloc_fcn  = jw_data_malloc,
    .realloc_fcn = jw_data_realloc,
    .free_fcn    = jw_data_free
};

static const char NS_DELIM = '#';


/*
  Convert expat ns<delim>local string to {ns}local.
  return NULL (OOM error) if allocation fails.
*/
static char * _toClarke(const char *expatName)
{
    size_t nlen;
    char *delim, *clarke, *ptr;

    delim = strrchr(expatName, NS_DELIM);
    nlen = strlen(expatName);
    ptr = clarke = (char*)jw_data_malloc(nlen + 3);

    if (!clarke)
    {
        return NULL;
    }

    if (!delim)
    {
        memcpy(ptr, "{}", 2);
        memcpy((ptr += 2), expatName, nlen + 1);
    }
    else
    {
        *ptr = '{';
        memcpy(++ptr, expatName, delim - expatName);
        *(ptr += (delim - expatName)) = '}';
        memcpy(++ptr, delim + 1, expatName + nlen - delim + 1);
    }

    return clarke;
}

static bool _hasError(jw_parser *parser)
{
    return parser->error.code != JW_ERR_NONE;
}

static void _freeNamespaces(jw_parser *parser)
{
    if (parser->namespaces)
    {
        jw_pool_destroy(parser->namespaces->pool);
    }
    parser->namespaces = parser->ns_tail = NULL;
}

/*
 * create a node from given context with ename, namespaces and attributes
 * returns NULL on error
 */
static jw_dom_node * _createNode(jw_dom_ctx  *context,
                                 const char  *ename,
                                 _ns_entry    namespaces,
                                 const char **atts,
                                 jw_err      *err)
{
    jw_dom_node *node;
    _ns_entry    nptr;
    char        *clarke;

    clarke = _toClarke(ename);
    if (!clarke)
    {
        JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
        return NULL;
    }

    if (!jw_dom_element_create_int(context, clarke, &node, err))
    {
        jw_data_free(clarke);
        return NULL;
    }
    jw_data_free(clarke);

    for (nptr = namespaces; nptr; nptr = nptr->next)
    {
        if (!jw_dom_put_namespace_int(node, nptr->prefix, nptr->uri, err))
        {
            return NULL;
        }
    }

    for (; *atts; atts += 2)
    {
        clarke = _toClarke(*atts);
        if (!clarke)
        {
            JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
            return NULL;
        }
        if (!jw_dom_set_attribute_int(node, clarke, *(atts + 1), err))
        {
            jw_data_free(clarke);
            return NULL;
        }
        jw_data_free(clarke);
    }

    return node;
}

static void _parserFreeUnhandledContext(jw_event_data evt,
                                        bool          result,
                                        void         *arg)
{
    UNUSED_PARAM(evt);
    UNUSED_PARAM(result);

    jw_dom_ctx *ctx = (jw_dom_ctx*)arg;
    jw_dom_context_destroy(ctx);
}

/* close off cdata buffer and create a text child in the current parsingNode */
static void _parserEndCharData(jw_parser *parser)
{
    jw_dom_node *textNode;
    jw_dom_ctx  *ctx;

    /* do nothing if in error state */
    if (parser->pnode_cdata && !_hasError(parser))
    {
        /* completing a text node for the current parent node */
        if (parser->parsing_node)
        {
            if (jw_dom_text_create_int(jw_dom_get_context(parser->parsing_node),
                                   parser->pnode_cdata, &textNode, &(parser->error)))
            {
                jw_dom_add_child(parser->parsing_node, textNode, &(parser->error));
            }
        }
        /* root text node, create, populate and event "parentless" text node */
        else if (jw_dom_context_create(&ctx, &(parser->error)))
        {
            if (jw_dom_text_create_int(ctx, parser->pnode_cdata, &textNode, &(parser->error)))
            {
                if (!jw_event_trigger(parser->event_element,
                                      textNode,
                                      _parserFreeUnhandledContext,
                                      ctx,
                                      &parser->error))
                {
                    jw_dom_context_destroy(ctx);
                }
            }
            else
            {
                jw_dom_context_destroy(ctx);
            }
        }
        jw_data_free(parser->pnode_cdata);
        parser->pnode_cdata = NULL;
    }
}

/******* expat callbacks *********/
static void _parserStartElement(
        void *userdata, const char *name, const char **atts)
{
    jw_parser   *parser;
    jw_dom_ctx  *ctx;
    jw_dom_node *node;

    parser = (jw_parser*) userdata;

    _parserEndCharData(parser);

    /* if parser is in a bad state (prior error), just return. caught by process later */
    if (_hasError(parser))
    {
        return;
    }
    /* stream open element */
    if (parser->streaming && !parser->opened)
    {
        if (jw_dom_context_create(&ctx, &(parser->error)))
        {
            node = _createNode(ctx, name, parser->namespaces, atts, &(parser->error));
            _freeNamespaces(parser);

            if (node)
            {
                parser->opened = true;
                if (!jw_event_trigger(parser->event_opened,
                                      node,
                                      _parserFreeUnhandledContext,
                                      ctx,
                                      &parser->error))
                {
                    jw_dom_context_destroy(ctx);
                }
            }
            else
            {
                jw_dom_context_destroy(ctx);
            }
        }
        return;
    }
    /* "root" or 1st level child when stream */
    if (!parser->parsing_node)
    {
        if (jw_dom_context_create(&ctx, &(parser->error)))
        {
            parser->parsing_node = _createNode(ctx, name, parser->namespaces, atts, &(parser->error));
            _freeNamespaces(parser);
            if (!parser->parsing_node)
            {
                jw_dom_context_destroy(ctx);
            }
        }
        return;
    }
    /* other children */
    ctx = jw_dom_get_context(parser->parsing_node);
    node = _createNode(ctx, name, parser->namespaces, atts, &(parser->error));
    _freeNamespaces(parser);

    if (node)
    {
        jw_dom_add_child(parser->parsing_node, node, &(parser->error));
        parser->parsing_node = node;
    }
}

static void _parserEndElement(void *userdata, const char *name)
{
    UNUSED_PARAM(name);

    jw_parser *parser;
    jw_dom_node *parent;
    jw_dom_ctx *ctx;

    parser = (jw_parser*) userdata;

    _parserEndCharData(parser);

    /* if parser is in a bad state (prior error), just return. caught by process later */
    if (_hasError(parser))
    {
        return;
    }

    if (parser->parsing_node)
    {
        parent = jw_dom_get_parent(parser->parsing_node);
        if (!parent) /* topmost (or 1rst level child of root) node */
        {
            ctx = jw_dom_get_context(parser->parsing_node);
            if (!jw_event_trigger(parser->event_element,
                                  parser->parsing_node,
                                  _parserFreeUnhandledContext,
                                  ctx,
                                  &parser->error))
            {
                jw_dom_context_destroy(ctx);
            }
        }
        parser->parsing_node = parent;
    }
    else
    {
        /* Closing an element that is not a parsing element -> closing root */
        parser->opened = false;
        if (!jw_event_trigger(parser->event_closed,
                              NULL,
                              NULL,
                              NULL,
                              &parser->error))
        {
            jw_log_err(JW_LOG_WARN, &parser->error, "event trigger failed");
        }
    }
}

static void _parserStartCharData(void *userdata, const char *str, int len)
{
    jw_parser *parser;
    size_t blen;

    parser = (jw_parser*) userdata;
    /* if parser is in a bad state (prior error), just return. caught by process later */
    if (_hasError(parser))
    {
        return;
    }
    /* add cdata to buffer that will be consumed when a new child is
      started or when the current element is closed. expat may call this
      event multiple times for each cdata section, as tokens (entities)
      get parsed.
      TODO: refactor to use evbuffer*/
    blen = jw_strlen(parser->pnode_cdata);

    parser->pnode_cdata = !parser->pnode_cdata ?
                             (char*)jw_data_malloc(len + 1) :
                             (char*)jw_data_realloc(parser->pnode_cdata, blen + len + 1 );
    if (!parser->pnode_cdata)
    {
        JABBERWERX_ERROR(&(parser->error), JW_ERR_NO_MEMORY);
        return;
    }
    memcpy(parser->pnode_cdata + blen, str, len);
    *(parser->pnode_cdata + blen + len) = '\0';
}

static void _addNamespace(jw_parser  *parser,
                          const char *prefix,
                          const char *uri,
                          jw_err     *err)
{
    _ns_entry entry;
    jw_pool  *pool;
    bool      created = false;

    pool = parser->namespaces ? parser->namespaces->pool : NULL;
    if (!pool)
    {
        if (!jw_pool_create(1024, &pool, err))
        {
            return; // bail: err will have been set
        }
        created = true;
    }

    if (!jw_pool_malloc(pool, sizeof(struct _ns_entry_t), (void *)&entry, err)
     || !jw_pool_strdup(pool, prefix ? prefix : "", &(entry->prefix), err)
     || !jw_pool_strdup(pool, uri ? uri : "", &(entry->uri), err))
    {
        // ensure we don't leak the pool if it were just created
        if (created)
        {
            jw_pool_destroy(pool);
        }
        return;
    }
    entry->pool = pool;
    entry->next = NULL;
    /* use a queue to keep ns order the same */
    if (!parser->namespaces)
    {
        parser->namespaces = entry;
    }
    if (parser->ns_tail)
    {
        parser->ns_tail->next = entry;
    }
    parser->ns_tail = entry;
}

/*
  Namespaces events are fired one at a time, before startElement call
*/
static void _parserStartNamespace(void       *userdata,
                                  const char *prefix,
                                  const char *uri)
{
    jw_parser *parser = (jw_parser*) userdata;
    if (!_hasError(parser))
    {
        _addNamespace(parser, prefix, uri, &(parser->error));
    }
}

static void _parserStartDoctypeDecl(void           *userdata,
                                    const XML_Char *doctypeName,
                                    const XML_Char *sysid,
                                    const XML_Char *pubid,
                                    int             has_internal_subset)
{
    UNUSED_PARAM(doctypeName);
    UNUSED_PARAM(sysid);
    UNUSED_PARAM(pubid);
    UNUSED_PARAM(has_internal_subset);
    jw_parser *parser = (jw_parser*) userdata;
    if (!_hasError(parser))
    {
        JABBERWERX_ERROR(&(parser->error), JW_ERR_BAD_FORMAT);
    }
    // unceremoniously stop.  Always an unforgivable error in our
    // world to send a DTD, due to the Billion Laughs attack.
    XML_StopParser(parser->parser, false);
}

/* free any mem allocated by parser, clear error state */
static void _parserClean(jw_parser *parser)
{
    if (parser->namespaces)
    {
        jw_pool_destroy(parser->namespaces->pool);
    }
    parser->namespaces = parser->ns_tail = NULL;
    if (parser->parsing_node)
    {
        jw_dom_context_destroy(jw_dom_get_context(parser->parsing_node));
    }
    parser->parsing_node = NULL;
    if (parser->pnode_cdata)
    {
        jw_data_free(parser->pnode_cdata);
    }
    parser->pnode_cdata = NULL;
}

static bool _parserReset(jw_parser *parser, jw_err *err)
{
    _parserClean(parser);

    if (parser->parser)
    {
        XML_ParserFree(parser->parser);
    }
    parser->parser = XML_ParserCreate_MM(NULL, &_xmlMs, &NS_DELIM);

    if (NULL == parser->parser)
    {
        JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
        return false;
    }

    //set the hash salt to a random number
    unsigned long salt;
    evutil_secure_rng_get_bytes(&salt,
                                sizeof(salt));
    XML_SetHashSalt(parser->parser, salt);

    XML_SetUserData(parser->parser,
                    parser);
    XML_SetElementHandler(parser->parser,
                          _parserStartElement,
                          _parserEndElement);
    XML_SetCharacterDataHandler(parser->parser,
                                _parserStartCharData);
    XML_SetNamespaceDeclHandler(parser->parser,
                               _parserStartNamespace,
                                NULL);
    XML_SetStartDoctypeDeclHandler(parser->parser,
                                   _parserStartDoctypeDecl);

    return true;
}

/* exported functions */
JABBERWERX_API bool jw_parser_create(bool        stream_parser,
                                     jw_parser **parser,
                                     jw_err     *err)
{
    assert(parser);

    jw_parser *result = jw_data_calloc(1, sizeof(struct _jw_parser));
    if (!result)
    {
        JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
        return false;
    }
    result->streaming = stream_parser;

    if (!jw_event_dispatcher_create(result, NULL, &result->dispatch, err) ||
        !jw_event_dispatcher_create_event(result->dispatch,
                                          JW_PARSER_EVENT_CLOSED,
                                          &result->event_closed,
                                          err) ||
        !jw_event_dispatcher_create_event(result->dispatch,
                                          JW_PARSER_EVENT_OPEN,
                                          &result->event_opened,
                                          err) ||
        !jw_event_dispatcher_create_event(result->dispatch,
                                          JW_PARSER_EVENT_ELEMENT,
                                          &result->event_element,
                                          err))
    {
        jw_parser_destroy(result);
        return false;
    }

    if (!_parserReset(result, err))
    {
        jw_parser_destroy(result);
        return false;
    }

    *parser = result;
    return true;
}

JABBERWERX_API void jw_parser_destroy(jw_parser *parser)
{
    assert(parser);

    _parserClean(parser);
    XML_ParserFree(parser->parser);
    if (parser->dispatch)
    {
        jw_event_dispatcher_destroy(parser->dispatch);
    }
    jw_data_free(parser);
}

JABBERWERX_API bool jw_parser_process(jw_parser       *parser,
                                      struct evbuffer *buffer,
                                      jw_err          *err)
{
    assert(parser);

    if (!buffer)
    {
        return true;
    }
    size_t bufflen, buffpos = 0;
    struct evbuffer_iovec v;

    assert(parser);
    bufflen = buffer ? evbuffer_get_length(buffer) : 0;
    while (!_hasError(parser) && (buffpos < bufflen))
    {
        evbuffer_peek(buffer, -1, NULL, &v, 1);
        if (!XML_Parse(parser->parser, v.iov_base, v.iov_len, false))
        {
            // don't overwrite an existing error, we can pass that one up
            // if there isn't one let's assume invalid arg and pass back
            // JW_ERR_INVALID_ARG
            if (!_hasError(parser))
            {
                JABBERWERX_ERROR(&(parser->error), JW_ERR_INVALID_ARG);
            }
            break;
        }
        buffpos += v.iov_len;
        evbuffer_drain(buffer, v.iov_len);
    }

    if (_hasError(parser))
    {
        JABBERWERX_ERROR(err, parser->error.code);
        _parserClean(parser); /* free mem and reset state */
        JABBERWERX_ERROR(&(parser->error), JW_ERR_INVALID_STATE);
        return false;
    }
    return true;
}

/* user data is a pointer to jw_dom_node **/
static void _xml_handler(jw_event_data evt, void *arg)
{
    jw_dom_node **_node = arg;
    jw_err err;

    *_node = evt->data;

    if (*_node && !jw_dom_context_retain(jw_dom_get_context(*_node), &err))
    {
        jw_log_err(JW_LOG_ERROR, &err, "could not retain node context");
        assert(false);
    }

    evt->handled = true;
}


JABBERWERX_API bool jw_parse_xml(const char   *source,
                                 jw_dom_node **parsed_dom,
                                 jw_err       *err)
{
    bool ret;
    struct evbuffer *buffer;

    /* parsed_dom becomes userdata passed through callback _XMLHandler */
    *parsed_dom = NULL;
    if (!jw_strlen(source))
    {
        return true; /* noop */
    }
    buffer = evbuffer_new();
    if (!buffer
        || (evbuffer_add_reference(buffer,
                                   source, strlen(source),
                                   NULL, NULL) == -1))
    {
        JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
        if (buffer)
        {
            evbuffer_free(buffer);
        }
        return false;
    }

    ret = jw_parse_xml_buffer(buffer, parsed_dom, err);

    /* must have at least one completed node */
    if (*parsed_dom == NULL)
    {
        JABBERWERX_ERROR(err, JW_ERR_INVALID_ARG);
    }
    else if (!ret)
    {
        /* have a dom but some parse error occurred, destroy dom */
        jw_dom_context_destroy(jw_dom_get_context(*parsed_dom));
        *parsed_dom = NULL;
    }

    evbuffer_free(buffer);
    return ret;
}

JABBERWERX_API bool jw_parse_xml_buffer(struct evbuffer *buffer,
                                        jw_dom_node    **parsed_dom,
                                        jw_err          *err)
{
    bool ret;
    size_t bufflen;
    jw_parser *parser = NULL;

    // parsed_dom becomes userdata passed through callback _XMLHandler
    *parsed_dom = NULL;
    bufflen = buffer ? evbuffer_get_length(buffer) : 0;

    if (!bufflen)
    {
        return true; /* noop */
    }

    ret = jw_parser_create(false,
                           &parser,
                           err)
          && jw_event_bind(jw_parser_event(parser, JW_PARSER_EVENT_ELEMENT),
                           _xml_handler,
                           (void*)parsed_dom,
                           err)
          && jw_parser_process(parser, buffer, err)
          && *parsed_dom != NULL;

    /* must have at least one completed node */
    if (*parsed_dom == NULL)
    {
        JABBERWERX_ERROR(err, JW_ERR_INVALID_ARG);
    }
    else if (!ret)
    {
        /* have a dom but some parse error occurred, destroy dom */
        jw_dom_context_destroy(jw_dom_get_context(*parsed_dom));
        *parsed_dom = NULL;
    }

    if (parser)
    {
        jw_parser_destroy(parser);
    }
    return ret;
}

JABBERWERX_API jw_event * jw_parser_event(jw_parser  *parser,
                                          const char *name)
{
    assert(parser != NULL);
    assert(name != NULL && *name != '\0');

    return jw_event_dispatcher_get_event(parser->dispatch, name);
}
