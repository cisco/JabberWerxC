/**
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

#include <jabberwerx/util/log.h>
#include <jabberwerx/util/htable.h>
#include <jabberwerx/util/serializer.h>

#include <assert.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define DEPTH_CONTEXT_POOL_SIZE   ((size_t)256)
#define DEPTH_CONTEXT_BUCKET_SIZE ((size_t)3)

/* tracks the namespace details for a given element depth */
typedef struct _depth_ctx_t
{
    struct _depth_ctx_t *parent;
    jw_pool             *pool;
    jw_htable           *namespaces;
    unsigned long        prefixCount;
    const char          *qname;
} *_depth_ctx;

/* the serializer details */
struct _jw_serializer
{
    struct evbuffer *output;
    bool             opened;
    _depth_ctx       depths;
};

/* tracks the details of a specific write "event" */
typedef struct _writer_t
{
    jw_serializer   *serializer;
    _depth_ctx       depth;
    struct evbuffer *nssBuffer;
    struct evbuffer *attrBuffer;
} *_writer;

static _depth_ctx _setup_depth_context(jw_serializer *s,
                                       jw_err        *err)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    union
    {
        _depth_ctx ctx;
        void      *ctxPtr;
    } ctxUnion;

    jw_pool   *pool = NULL;
    _depth_ctx ctx  = NULL;

    if (!jw_pool_create(DEPTH_CONTEXT_POOL_SIZE, &pool, err))
    {
        jw_log(JW_LOG_WARN, "failed to create depth context pool");
        goto _setup_depth_context_done_label;
    }
    if (!jw_pool_calloc(
            pool, 1, sizeof(struct _depth_ctx_t), &ctxUnion.ctxPtr, err))
    {
        jw_log(JW_LOG_WARN, "failed to create depth context");
        goto _setup_depth_context_done_label;
    }
    
    ctx = ctxUnion.ctx;
    ctx->pool = pool;
    ctx->parent = s->depths;
    s->depths = ctx;
    pool = NULL;

_setup_depth_context_done_label:
    if (pool)
    {
        // destroys htable(s) with cleaners
        jw_pool_destroy(pool);
        ctx = NULL;
    }

    return ctx;
}

static _depth_ctx _teardown_depth_context(_depth_ctx depth)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    _depth_ctx parent;

    if (!depth)
    {
        return NULL;
    }

    parent = depth->parent;
    if (depth->namespaces)
    {
        jw_htable_destroy(depth->namespaces);
    }
    jw_pool_destroy(depth->pool);

    return parent;
}

// writes a value, escaping as needed
static bool _write_value(struct evbuffer *buffer,
                         const char      *val,
                         bool             full,
                         jw_err          *err)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    char       *match;
    const char *expr = (full) ? "&<>\"\'" : "&<>";
    const char *pos  = val;

    while (pos && (match = strpbrk(pos, expr)))
    {
        const char *subst = NULL;
        size_t      len   = 0;
        size_t      bgn   = (ptrdiff_t)match - (ptrdiff_t)pos;

        switch (*match)
        {
            case '\'': subst = "&apos;"; len = 6; break;
            case '\"': subst = "&quot;"; len = 6; break;
            case '&':  subst = "&amp;";  len = 5; break;
            case '<':  subst = "&lt;";   len = 4; break;
            case '>':  subst = "&gt;";   len = 4; break;
            default:
                // should never get here
                jw_log(JW_LOG_ERROR, "unhandled delimiter: %c", *match);
                assert(false);
        }

        // write the preamble
        if (-1 == evbuffer_add(buffer, pos, bgn))
        {
            jw_log(JW_LOG_WARN, "failed to write segment preamble");
            JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
            return false;
        }

        // write the substitution
        if (-1 == evbuffer_add(buffer, subst, len))
        {
            jw_log(JW_LOG_WARN, "failed to write escaped token");
            JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
            return false;
        }

        pos = match + 1;
    }

    // write the remainder
    if (-1 == evbuffer_add(buffer, pos, strlen(pos)))
    {
        jw_log(JW_LOG_WARN, "failed to write segment remainder");
        JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
        return false;
    }

    return true;
}

// sets up the namespace mapping for the given context
static const char *_put_namespace_mapping(_writer     w,
                                          const char *uri,
                                          const char *prefix,
                                          bool        dup,
                                          jw_err     *err)
{
    JW_LOG_TRACE_FUNCTION("uri='%s'; prefix='%s'", uri, prefix);

    _depth_ctx depth = w->depth;

    if (!depth->namespaces)
    {
        // setup mapping
        if (!jw_htable_create(DEPTH_CONTEXT_BUCKET_SIZE,
                              jw_str_hashcode,
                              jw_str_compare,
                              &depth->namespaces,
                              err))
        {
            jw_log(JW_LOG_WARN, "failed to create namespace map");
            return NULL;
        }
    }

    // dup for storage
    if (dup &&
        (!jw_pool_strdup(depth->pool, prefix, (char **)&prefix, err)
         || !jw_pool_strdup(depth->pool, uri, (char **)&uri, err)))
    {
        jw_log(JW_LOG_WARN, "failed to duplicate namespace data");
        return NULL;
    }

    // remember mapping
    if (!jw_htable_put(depth->namespaces, uri, (char *)prefix, NULL, err))
    {
        jw_log(JW_LOG_WARN, "failed to add namespace to map");
        return NULL;
    }

    // declare it!
    if (!w->nssBuffer && !(w->nssBuffer = evbuffer_new()))
    {
        jw_log(JW_LOG_WARN, "failed to allocate namespace buffer");
        JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
        return NULL;
    }

    if (prefix[0])
    {
        if (-1 ==
               evbuffer_add_printf(w->nssBuffer, " xmlns:%s='%s'", prefix, uri))
        {
            jw_log(JW_LOG_WARN, "failed to write prefixed namespace to buffer");
            JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
            return NULL;
        }
    }
    else
    {
        if (-1 == evbuffer_add_printf(w->nssBuffer, " xmlns='%s'", uri))
        {
            jw_log(JW_LOG_WARN, "failed to write namespace to buffer");
            JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
            return NULL;
        }
    }

    return prefix;
}

// locates a mapping for the given URI
static const char *_find_namespace_prefix(_depth_ctx  d,
                                          const char *uri,
                                          jw_err     *err)
{
    JW_LOG_TRACE_FUNCTION("uri='%s'", uri);

    const char *prefix = NULL;

    if (strncmp("http://www.w3.org/XML/1998/namespace", uri, 36) == 0)
    {
        // can only be this; short-circuit other logic
        return "xml";
    }
    else if (d && d->namespaces)
    {
        prefix = jw_htable_get(d->namespaces, uri);
    }

    if (!prefix && d->parent)
    {
        jw_hnode *n;

        prefix = _find_namespace_prefix(d->parent, uri, err);

        if (d->namespaces)
        {
            for (n = jw_htable_get_first_node(d->namespaces);
                 prefix != NULL && n != NULL;
                 n = jw_htable_get_next_node(d->namespaces, n))
            {
                if (0 == strcmp(uri, jw_hnode_get_key(n))
                 && 0 != strcmp(prefix, jw_hnode_get_value(n)))
                {
                    // prefix mapped to different namespace; return NULL
                    return NULL;
                }
            }
        }
    }

    return prefix;
}

static const char *_make_qname(_writer     w,
                               const char *nsURI,
                               const char *lname,
                               bool        in_attr,
                               jw_err     *err)
{
    JW_LOG_TRACE_FUNCTION("nsURI='%s'; lname='%s'", nsURI, lname);

    _depth_ctx  depth = w->depth;
    const char *prefix;

    union
    {
        const char *qn;
        void       *qnPtr;
    } qnUnion;
    qnUnion.qn = lname;

    if (in_attr && '\0' == nsURI[0])
    {
        // attribute in the 'non' namespace; always 'non' prefix
        prefix = "";
    }
    else
    {
        prefix = _find_namespace_prefix(depth, nsURI, err);
        if (in_attr && prefix && prefix[0] == '\0')
        {
            // attribute in other namespace; needs prefix
            prefix = NULL;
        }
    }

    if (!prefix)
    {
        // need to generate a prefix
        jw_htable *namespaces = depth->namespaces;
        char            mapped[19];
        bool            valid = false;

        // holds "ns" + hex(counter) + NULL
        mapped[0] = '\0';
        do
        {
            jw_hnode *n;

            if (in_attr)
            {
                if (0 > sprintf(mapped, "ns%lx", depth->prefixCount++))
                {
                    jw_log(JW_LOG_ERROR, "failed to generate prefix");
                    assert(false);
                }
            }
            in_attr = true;
            valid   = true;

            if (namespaces)
            {
                for (n = jw_htable_get_first_node(namespaces);
                     valid && n != NULL;
                     n = jw_htable_get_next_node(namespaces, n))
                {
                    valid = (0 != strcmp(jw_hnode_get_value(n), mapped));
                }
            }
        }
        while (!valid);

        prefix = _put_namespace_mapping(w, nsURI, mapped, true, err);
        if (!prefix)
        {
            return NULL;
        }
    }

    if (prefix[0] != '\0')
    {
        if (!jw_pool_malloc(depth->pool,
                            strlen(lname) + strlen(prefix) + 2,
                            &qnUnion.qnPtr,
                            err))
        {
            jw_log(JW_LOG_WARN, "failed to allocate prefixed namespace");
            return NULL;
        }
        if (0 > sprintf((char *)qnUnion.qn, "%s:%s", prefix, lname))
        {
            jw_log(JW_LOG_ERROR, "failed to write prefixed namespace");
            assert(false);
        }
    }

    return qnUnion.qn;
}

static bool _write_element_start(jw_serializer *s,
                                 jw_dom_node   *elem,
                                 bool           starting,
                                 jw_err        *err)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    struct _writer_t writer;
    jw_dom_node     *child;

    // (most likely) need to strdup namespace prefixes/URIs if root level
    bool dupNss = (s->depths == NULL);
    bool result = false;

    // prepare a context for this depth
    memset(&writer, 0, sizeof(struct _writer_t));
    // TODO: make this step smarter??
    writer.serializer = s;
    writer.depth = _setup_depth_context(s, err);
    if (!writer.depth)
    {
        jw_log(JW_LOG_WARN, "failed to set up element start depth context");
        result = false;
        goto _write_element_start_done_label;
    }

    // setup namespaces
    for (child = jw_dom_get_first_namespace(elem);
         child != NULL;
         child = jw_dom_get_sibling(child))
    {
        const char *prefix = jw_dom_get_ename(child);
        const char *uri    = jw_dom_get_value(child);

        // create as needed
        if (!writer.nssBuffer && !(writer.nssBuffer = evbuffer_new()))
        {
            jw_log(JW_LOG_WARN, "failed to allocate element start buffer");
            JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
            goto _write_element_start_done_label;
        }

        prefix = _put_namespace_mapping(&writer, uri, prefix, dupNss, err);
        if (!prefix)
        {
            jw_log(JW_LOG_WARN, "failed to put namespace mapping");
            goto _write_element_start_done_label;
        }
    }

    // setup attributes
    for (child = jw_dom_get_first_attribute(elem);
         child != NULL;
         child = jw_dom_get_sibling(child))
    {
        const char *qname;
        const char *val;

        // create as needed
        if (!writer.attrBuffer && !(writer.attrBuffer = evbuffer_new()))
        {
            jw_log(JW_LOG_WARN, "failed to allocate attribute buffer");
            JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
            goto _write_element_start_done_label;
        }

        qname = _make_qname(&writer,
                            jw_dom_get_namespace_uri(child),
                            jw_dom_get_localname(child),
                            true,
                            err);
        if (!qname)
        {
            jw_log(JW_LOG_WARN, "failed to create qname");
            goto _write_element_start_done_label;
        }

        if (-1 == evbuffer_add_printf(writer.attrBuffer, " %s='", qname))
        {
            jw_log(JW_LOG_WARN, "failed to write attribute to buffer");
            JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
            goto _write_element_start_done_label;
        }

        val = jw_dom_get_value(child);
        if (!_write_value(writer.attrBuffer, val, true, err))
        {
            jw_log(JW_LOG_WARN, "failed to write attribute");
            goto _write_element_start_done_label;
        }
        if (-1 == evbuffer_add(writer.attrBuffer, "'", 1))
        {
            jw_log(JW_LOG_WARN,
                   "failed to write closing quote to attribute buffer");
            JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
            goto _write_element_start_done_label;
        }
    }

    // element tag proper
    writer.depth->qname = _make_qname(&writer,
                                      jw_dom_get_namespace_uri(elem),
                                      jw_dom_get_localname(elem),
                                      false,
                                      err);
    if (!writer.depth->qname)
    {
        jw_log(JW_LOG_WARN, "failed to create element qname");
        goto _write_element_start_done_label;
    }
    if (-1 == evbuffer_add_printf(s->output, "<%s", writer.depth->qname))
    {
        jw_log(JW_LOG_WARN, "failed to write element start to buffer");
        JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
        goto _write_element_start_done_label;
    }

    if (writer.nssBuffer &&
        -1 == evbuffer_add_buffer(s->output, writer.nssBuffer))
    {
        jw_log(JW_LOG_WARN, "failed to add namespace buffer to output");
        JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
        goto _write_element_start_done_label;
    }
    if (writer.attrBuffer &&
        -1 == evbuffer_add_buffer(s->output, writer.attrBuffer))
    {
        jw_log(JW_LOG_WARN, "failed to add attribute buffer to output");
        JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
        goto _write_element_start_done_label;
    }

    if (starting || jw_dom_get_first_child(elem))
    {
        s->opened = starting = true;
        if (evbuffer_add(s->output, ">", 1) == -1)
        {
            jw_log(JW_LOG_WARN, "failed to write closing brace to element");
            JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
            goto _write_element_start_done_label;
        }

        if (!jw_pool_strdup(writer.depth->pool,
                            writer.depth->qname,
                            (char **)&writer.depth->qname,
                            err))
        {
            jw_log(JW_LOG_WARN, "failed to duplicate qname");
            goto _write_element_start_done_label;
        }
    }
    else
    {
        starting = false;
        if (-1 == evbuffer_add(s->output, "/>", 2))
        {
            jw_log(JW_LOG_WARN,
                   "failed to write closing brace to childless element");
            JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
            goto _write_element_start_done_label;
        }
    }

    // if we got here, we're done!
    result = true;

_write_element_start_done_label:
    if (writer.nssBuffer)
    {
        evbuffer_free(writer.nssBuffer);
    }
    if (writer.attrBuffer)
    {
        evbuffer_free(writer.attrBuffer);
    }
    if (!starting && writer.depth)
    {
        s->depths = _teardown_depth_context(writer.depth);
    }

    return result;
}

static bool _write_element_end(jw_serializer *s,
                               jw_err        *err)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    bool result = false;

    if (-1 == evbuffer_add_printf(s->output, "</%s>", s->depths->qname))
    {
        jw_log(JW_LOG_WARN, "failed to write element end");
        JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
        goto finished;
    }
    result = true;

    finished:
    s->depths = _teardown_depth_context(s->depths);

    return result;
}


///////////////////////////
// public API
//

JABBERWERX_API bool jw_serializer_create(struct evbuffer *out,
                                         jw_serializer  **ser,
                                         jw_err          *err)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    jw_serializer *s = NULL;

    assert(out);
    assert(ser);

    s = jw_data_calloc(1, sizeof(struct _jw_serializer));
    if (!s)
    {
        jw_log(JW_LOG_WARN, "failed to allocate serializer");
        JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
        return false;
    }

    s->output = out;
    *ser = s;

    return true;
}

JABBERWERX_API void jw_serializer_destroy(jw_serializer *ser)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(ser);

    while (ser->depths)
    {
        ser->depths = _teardown_depth_context(ser->depths);
    }
    jw_data_free(ser);
}

JABBERWERX_API struct evbuffer *jw_serializer_get_output(jw_serializer *ser)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(ser);
    return ser->output;
}
JABBERWERX_API bool jw_serializer_is_open(jw_serializer *ser)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(ser);
    return ser->opened;
}

JABBERWERX_API bool jw_serializer_write_start(jw_serializer *ser,
                                              jw_dom_node   *root,
                                              jw_err        *err)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(jw_dom_get_nodetype(root) == JW_DOM_TYPE_ELEMENT);
    if (jw_serializer_is_open(ser))
    {
        jw_log(JW_LOG_WARN,
               "cannot open root element: serializer already open");
        JABBERWERX_ERROR(err, JW_ERR_INVALID_STATE);
        return false;
    }

    if (!_write_element_start(ser, root, true, err))
    {
        jw_log(JW_LOG_WARN, "failed to write element start");
        return false;
    }
    ser->opened = true;

    return true;
}

JABBERWERX_API bool jw_serializer_write(jw_serializer *ser,
                                        jw_dom_node   *node,
                                        jw_err        *err)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(ser);
    jw_dom_nodetype type = jw_dom_get_nodetype(node);

    switch (type)
    {
    case JW_DOM_TYPE_TEXT:
    {
        if (!ser->opened)
        {
            jw_log(JW_LOG_WARN,
                   "cannot write element: serializer not yet open");
            JABBERWERX_ERROR(err, JW_ERR_INVALID_ARG);
            return false;
        }

        // TODO: escape text val
        const char *val = jw_dom_get_value(node);
        if (!_write_value(ser->output, val, false, err))
        {
            jw_log(JW_LOG_WARN, "failed to write text");
            return false;
        }
        break;
    }

    case JW_DOM_TYPE_ELEMENT:
    {
        jw_dom_node *child = jw_dom_get_first_child(node);
        bool              open  = ser->opened;
        bool              empty = child == NULL;

        // open this element
        if (!_write_element_start(ser, node, false, err))
        {
            jw_log(JW_LOG_WARN, "failed to write element start");
            return false;
        }

        // write the children (if any)
        for ( ; child != NULL; child = jw_dom_get_sibling(child))
        {
            if (!jw_serializer_write(ser, child, err))
            {
                jw_log(JW_LOG_WARN, "failed to write element children");
                return false;
            }
        }

        // write the close tag, if necessary
        if (!empty && !_write_element_end(ser, err))
        {
            jw_log(JW_LOG_WARN, "failed to write element close");
            return false;
        }

        // if this call opened the serializer, then close it
        if (!open)
        {
            ser->opened = false;
        }
        break;
    }

    default:
        jw_log(JW_LOG_ERROR, "unhandled node type: %d", type);
        assert(false);
    }

    return true;
}

JABBERWERX_API bool jw_serializer_write_end(jw_serializer *ser,
                                            jw_err        *err)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    if (!jw_serializer_is_open(ser))
    {
        jw_log(JW_LOG_WARN,
               "cannot write element end: serializer not yet open");
        JABBERWERX_ERROR(err, JW_ERR_INVALID_STATE);
        return false;
    }

    if (!_write_element_end(ser, err))
    {
        jw_log(JW_LOG_WARN, "failed to write element end");
        return false;
    }
    ser->opened = false;

    return true;
}

JABBERWERX_API bool jw_serialize_xml(jw_dom_node *dom,
                                     char       **xml,
                                     size_t      *len,
                                     jw_err      *err)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    bool result = false;

    assert(jw_dom_get_nodetype(dom) == JW_DOM_TYPE_ELEMENT);
    assert(xml);

    struct evbuffer *buffer = evbuffer_new();
    char            *output = NULL;
    if (!buffer)
    {
        jw_log(JW_LOG_WARN, "failed to allocate serialization buffer");
        JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
        goto jw_serialize_xml_done_label;
    }
    size_t mnt = evbuffer_get_length(buffer);

    if (!jw_serialize_xml_buffer(dom, buffer, &mnt, err))
    {
        jw_log(JW_LOG_WARN, "failed to serialize dom");
        goto jw_serialize_xml_done_label;
    }

    output = jw_data_malloc(mnt+1);
    if (!output)
    {
        jw_log(JW_LOG_WARN, "failed to allocate output string");
        JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
        goto jw_serialize_xml_done_label;
    }

    if (-1 == evbuffer_copyout(buffer, output, mnt))
    {
        jw_log(JW_LOG_WARN, "failed to copy to output string");
        JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
        goto jw_serialize_xml_done_label;
    }

    // ensure output is NULL terminated
    output[mnt] = '\0';
    if (len)
    {
        *len = mnt;
    }
    result = true;
    *xml = output;
    output = NULL;

jw_serialize_xml_done_label:
    if (buffer)
    {
        evbuffer_free(buffer);
    }
    if (output)
    {
        jw_data_free(output);
    }

    return result;
}

JABBERWERX_API bool jw_serialize_xml_buffer(jw_dom_node     *dom,
                                            struct evbuffer *buffer,
                                            size_t          *len,
                                            jw_err          *err)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    jw_serializer *ser    = NULL;
    bool                result = false;

    assert(jw_dom_get_nodetype(dom) == JW_DOM_TYPE_ELEMENT);
    size_t orig_len = evbuffer_get_length(buffer);

    struct evbuffer *outbuff = evbuffer_new();
    if (!outbuff)
    {
        jw_log(JW_LOG_WARN, "failed to allocate serialization buffer");
        JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
        goto jw_serialize_xml_buffer_done_label;
    }
    if (!jw_serializer_create(outbuff, &ser, err))
    {
        jw_log(JW_LOG_WARN, "failed to create serializer");
        goto jw_serialize_xml_buffer_done_label;
    }
    if (!jw_serializer_write(ser, dom, err))
    {
        jw_log(JW_LOG_WARN, "failed to write dom");
        goto jw_serialize_xml_buffer_done_label;
    }

    if (-1 == evbuffer_add_buffer(buffer, outbuff))
    {
        jw_log(JW_LOG_WARN, "failed to add serialized buffer to output");
        goto jw_serialize_xml_buffer_done_label;
    }

    size_t new_len = evbuffer_get_length(buffer);
    size_t mnt     = new_len - orig_len;

    if (len)
    {
        *len = (size_t)mnt;
    }
    result = true;

jw_serialize_xml_buffer_done_label:
    if (ser)
    {
        jw_serializer_destroy(ser);
    }
    if (outbuff)
    {
        evbuffer_free(outbuff);
    }

    return result;
}
