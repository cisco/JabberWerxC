/**
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

#include <stdio.h>
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <jabberwerx/dom.h>
#include <jabberwerx/util/htable.h>
#include <jabberwerx/util/mem.h>
#include <jabberwerx/util/log.h>
#include "include/dom_int.h"


/**
 * Internal Constants
 * \todo Make this configurable?
 */
/* size of DOM memory pool */
#define DOM_CONTEXT_POOL_SIZE   1024
/* initial bucks in DOM strings table */
#define DOM_CONTEXT_BUCKET_SIZE 9

/**
 * bitmasks for parts of expanded-names
 */
/* localname part */
#define DOM_ENAME_LOCALNAME (1 << 1)
/* namespace part */
#define DOM_ENAME_NAMESPACE (1 << 2)
/* complete expanded name */
#define DOM_ENAME_FULL      (DOM_ENAME_LOCALNAME|DOM_ENAME_NAMESPACE)
/* part(s) is/are optional */
#define DOM_ENAME_OPTIONAL  (1 << 0)

#ifdef DEBUG_REFCOUNT
#include <execinfo.h>

#define KEEP_STACK 16
// Most recent created.
static jw_dom_ctx *g_all_contexts = NULL;
#endif // DEBUG_REFCOUNT

/**
 * Internal Structures
 */

struct _jw_dom_node
{
    jw_dom_ctx          *context;
    jw_dom_nodetype      type;
    const char          *ename;
    const char          *lname;
    const char          *nsURI;
    const char          *value;
    struct _jw_dom_node *parent;
    struct _jw_dom_node *siblingPrev;
    struct _jw_dom_node *siblingNext;
    /* first attribute in element */
    struct _jw_dom_node *attrs;
    /* first namespace in element */
    struct _jw_dom_node *nss;
    /* first and last for easy insertion */
    struct _jw_dom_node *childrenFirst;
    struct _jw_dom_node *childrenLast;
};

typedef struct _jw_dom_nodelist_t
{
    jw_dom_node                data;
    struct _jw_dom_nodelist_t *next;
} *_jw_dom_nodelist;

struct _jw_dom_ctx
{
    jw_pool         *pool;
    // pseudo-interning of (most) strings
    jw_htable       *strings;
    // MOST RECENT node created
    _jw_dom_nodelist nodes;
    // context refcount
    int32_t          refCount;
#ifdef DEBUG_REFCOUNT
    jw_dom_ctx      *next;
    jw_dom_ctx      *prev;
    int              createStackSize;
    void            *createStack[KEEP_STACK];
#endif // DEBUG_REFCOUNT
};

typedef bool (*_validateUTF8Fn)(const char *);
typedef bool (*_validateENameFn)(const char *, int);

/**
 * Internal Functions
 */

static void _detachNode(jw_dom_node *node);
static void _attachNode(jw_dom_node *node, jw_dom_node *prev);

static int _intern_str_cmp(const void *s1, const void *s2)
{
    if (s1 == s2)
    {
        return 0;
    }

    return strcmp((const char *)s1, (const char *)s2);
}

static bool _validateNMChar(uint32_t codepoint, size_t idx)
{
    if ((codepoint == '_') ||
        (codepoint >= 'A' && codepoint <= 'Z') ||
        (codepoint >= 'a' && codepoint <= 'z') ||
        (codepoint >= 0xc0 && codepoint <= 0xd6) ||
        (codepoint >= 0xd8 && codepoint <= 0xf6) ||
        (codepoint >= 0xf8 && codepoint <= 0x2ff) ||
        (codepoint >= 0x370 && codepoint <= 0x37d) ||
        (codepoint >= 0x37f && codepoint <= 0x1fff) ||
        (codepoint >= 0x200c && codepoint <= 0x200d) ||
        (codepoint >= 0x2070 && codepoint <= 0x218f) ||
        (codepoint >= 0x2c00 && codepoint <= 0x2fef) ||
        (codepoint >= 0x3001 && codepoint <= 0xd7ff) ||
        (codepoint >= 0xf900 && codepoint <= 0xfdcf) ||
        (codepoint >= 0x10000 && codepoint <= 0xeffff))
    {
        return true;
    }
    else if (idx > 0 && ((codepoint == '-') ||
                         (codepoint == '.') ||
                         (codepoint >= '0' && codepoint <= '9') ||
                         (codepoint == 0xb7) ||
                         (codepoint >= 0x300 && codepoint <= 0x36f) ||
                         (codepoint >= 0x203f && codepoint <= 2040)))
    {
        return true;
    }

    return false;
}

/*
  From Unicode 3.2 http://www.unicode.org/reports/tr28/tr28-3.html
  Table 3.1B Legal UTF-8 Byte Sequences

    1st Byte    2nd Byte        3rd Byte        4th Byte
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
typedef bool (*_utf8_validator)(uint32_t codepoint, size_t idx);
static bool _doValidateUTF8(const char    **text,
                            uint8_t         term,
                            _utf8_validator extra)
{
    uint32_t        codepoint;
    size_t          cnt = 0;
    size_t          idx = 0;
    const uint8_t   *inptr = (const uint8_t *)*text;

    while (*inptr != term)
    {
        cnt = 0;
        if (*inptr == 0x00)
        {
            jw_log(JW_LOG_DEBUG, "premature end of string at index %zd", idx);
            return false;
        }

        // 1-byte codepoint (0xxxxxxx)
        if (0x7f >= *inptr)
        {
            codepoint = inptr[0];
            cnt = 1;
        }
        // 2-byte codepoint (110xxxxx 10xxxxxx)
        else if (0xc2 <= inptr[0] && 0xdf >= inptr[0] &&
                 0x80 <= inptr[1] && 0xbf >= inptr[1])
        {
            codepoint = ((inptr[0] & 0x1f) << 6) |
                        (inptr[1] & 0x3f);
            cnt = 2;
        }
        // 3-byte codepoint (1110xxxx 10xxxxxx 10xxxxxx)
        else if (((0xe0 == inptr[0] &&
                   0xa0 <= inptr[1] && 0xbf >= inptr[1]) ||
                  (0xe1 <= inptr[0] && 0xec >= inptr[0] &&
                   0x80 <= inptr[1] && 0xbf >= inptr[1]) ||
                  (0xed == inptr[0] &&
                   0x80 <= inptr[1] && 0x9f >= inptr[1]) ||
                  (0xee <= inptr[0] && 0xef >= inptr[0] &&
                   0x80 <= inptr[1] && 0xbf >= inptr[1])) &&
                 0x80 <= inptr[2] && 0xbf >= inptr[2])
        {
            codepoint = ((inptr[0] & 0x0f) << 12) |
                        ((inptr[1] & 0x3f) << 6) |
                        (inptr[2] & 0x3f);
            cnt = 3;
        }
        // 4-byte codepoint (11110xxx 10xxxxxx 10xxxxxx 10xxxxxx)
        else if (((0xf0 == inptr[0] &&
                   0x90 <= inptr[1] && 0xbf >= inptr[1]) ||
                  (0xf1 <= inptr[0] && 0xf3 >= inptr[0] &&
                   0x80 <= inptr[1] && 0xbf >= inptr[1]) ||
                  (0xf4 == inptr[0] &&
                   0x80 <= inptr[1] && 0x8f >= inptr[1]) ||
                  (0xf5 <= inptr[0] && 0xf7 >= inptr[0] &&
                   0x80 <= inptr[1] && 0xbf >= inptr[1])) &&
                 0x80 <= inptr[2] && 0xbf >= inptr[2] &&
                 0x80 <= inptr[3] && 0xbf >= inptr[3])
        {
            codepoint = ((inptr[0] & 0x07) << 18) |
                        ((inptr[1] & 0x3f) << 12) |
                        ((inptr[2] & 0x3f) << 6) |
                        (inptr[3] & 0x3f);
            cnt = 4;
        }
        // 5-byte codepoint (1111-10xx 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx)
        else if (0xf8 <= inptr[0] && 0xfb >= inptr[0] &&
                 0x80 <= inptr[1] && 0xbf >= inptr[1] &&
                 0x80 <= inptr[2] && 0xbf >= inptr[2] &&
                 0x80 <= inptr[3] && 0xbf >= inptr[3] &&
                 0x80 <= inptr[4] && 0xbf >= inptr[4])
        {
            codepoint = ((inptr[0] & 0x03) << 24) |
                        ((inptr[1] & 0x3f) << 18) |
                        ((inptr[2] & 0x3f) << 12) |
                        ((inptr[3] & 0x3f) << 6) |
                        (inptr[4] & 0x3f);
            cnt = 5;
        }
        // 6-byte codepoint (1111-110x 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx)
        else if (0xfc <= inptr[0] && 0xfd >= inptr[0] &&
                 0x80 <= inptr[1] && 0xbf >= inptr[1] &&
                 0x80 <= inptr[2] && 0xbf >= inptr[2] &&
                 0x80 <= inptr[3] && 0xbf >= inptr[3] &&
                 0x80 <= inptr[4] && 0xbf >= inptr[4] &&
                 0x80 <= inptr[5] && 0xbf >= inptr[5])
        {
            codepoint = ((inptr[0] & 0x01) << 30) |
                        ((inptr[1] & 0x3f) << 24) |
                        ((inptr[2] & 0x3f) << 18) |
                        ((inptr[3] & 0x3f) << 12) |
                        ((inptr[4] & 0x3f) << 6) |
                        (inptr[5] & 0x3f);
            cnt = 6;
        }
        else
        {
            jw_log(JW_LOG_DEBUG, "malformed code sequence at index %zd", idx);
            return false;
        }

        if (extra && !extra(codepoint, idx))
        {
            jw_log(JW_LOG_DEBUG, "invalid code sequence at index %zd", idx);
            return false;
        }

        idx += cnt;
        inptr += cnt;
    }

    *text = (const char *)inptr;

    return true;
}

static bool _noValidateUTF8(const char *text)
{
    UNUSED_PARAM(text);
    return true;
}

static bool _validateUTF8(const char *text)
{
    const char *end = text;
    return _doValidateUTF8(&end, '\0', NULL);
}

static bool _noValidateEName(const char *name, int type)
{
    UNUSED_PARAM(name);
    UNUSED_PARAM(type);
    return true;
}

static bool _validateEName(const char *name, int type)
{
    bool        opt = (type & DOM_ENAME_OPTIONAL) == DOM_ENAME_OPTIONAL;
    const char *lname = NULL;
    const char *end = name;

    if ((type & DOM_ENAME_NAMESPACE) == DOM_ENAME_NAMESPACE)
    {
        if (name[0] == '{')
        {
            end++;
            if (!_doValidateUTF8(&end, '}', NULL))
            {
                return false;
            }

            /* end should now point to start of localname */
            end++;
        }
        else if (!opt)
        {
            /* namespace required, but missing */
            return false;
        }
    }

    if ((type & DOM_ENAME_LOCALNAME) == DOM_ENAME_LOCALNAME)
    {
        lname = end;

        if (!_doValidateUTF8(&end, '\0', _validateNMChar))
        {
            /* invalid characters */
            return false;
        }
        if ((lname == end) && !opt)
        {
            /* 0-length name */
            return false;
        }
    }

    return true;
}

static const char * _internString(jw_dom_ctx *context,
                                  const char *str,
                                  bool        findit,
                                  jw_err     *err)
{
    char    *lookup;

    lookup = (findit) ?
             (char *)jw_htable_get(context->strings, str) :
             NULL;
    if (!lookup)
    {
        if (!jw_pool_strdup(context->pool, str, &lookup, err))
        {
            return NULL;
        }

        /* add dup only! */
        if (!jw_htable_put(context->strings, lookup, lookup, NULL, err))
        {
            return NULL;
        }
    }

    return lookup;
}

static bool _compareEName(const char *pattern,
                          const char *target,
                          bool        no_ns)
{
    size_t      ptnLen, tgtLen;
    const char  *tgtLN;

    if (_intern_str_cmp(pattern, target) == 0)
    {
        /* complete pattern matches */
        return true;
    }

    tgtLN = strrchr(target, '}') + 1;
    ptnLen = strlen(pattern);
    if (pattern[0] == '{')
    {
        if (no_ns)
        {
            /* don't care about namespace-only match */
            return false;
        }

        tgtLen = tgtLN - target;
        if (ptnLen != tgtLen)
        {
            /* sizes don't match; namespace doesn't match */
            return false;
        }

        if (strncmp(pattern, target, ptnLen) != 0)
        {
            /* namespace pattern does not match target */
            return false;
        }
    }
    else
    {
        tgtLen = strlen(tgtLN);
        if (ptnLen != tgtLen)
        {
            /* sizes don't match; localname doesn't match */
            return false;
        }

        if (strncmp(pattern, tgtLN, ptnLen) != 0)
        {
            /* localname pattern does not match */
            return false;
        }
    }

    return true;
}

static const char * _internEName(jw_dom_node     *node,
                                 const char      *str,
                                 int              type,
                                 _validateENameFn validateENameFn,
                                 jw_err          *err)
{
    jw_dom_ctx *context = node->context;
    const char *lookup;

    lookup = (char *)jw_htable_get(context->strings, str);
    if (!lookup)
    {
        /* validate correctness first */
        if (!validateENameFn(str, type))
        {
            JABBERWERX_ERROR(err, JW_ERR_INVALID_ARG);
            return NULL;
        }

        lookup = _internString(context, str, false, err);
        if (!lookup)
        {
            return NULL;
        }
    }
    node->ename = lookup;

    if ((type & DOM_ENAME_FULL) == DOM_ENAME_FULL)
    {
        size_t  len;
        char    tmp[1024];
        char    *nsURI;
        char    *lname;

        /* intern localname */
        lname = strrchr(lookup, '}') + 1;
        node->lname = _internString(context, lname, true, err);
        if (!node->lname)
        {
            return NULL;
        }

        /* intern namespaceURI */
        /* this is a temporary alloc, to be compatible with htable */
        len = (uintptr_t)(lname - 1) - (uintptr_t)(lookup + 1);
        if (len >= sizeof(tmp))
        {
            nsURI = (char *)jw_data_malloc(len + 1);
            if (!nsURI)
            {
                JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
                return NULL;
            }
        }
        else
        {
            nsURI = tmp;
        }
        memcpy((void *)nsURI, lookup + 1, len);
        nsURI[len] = '\0';
        node->nsURI = _internString(context, nsURI, true, err);
        if (len >= sizeof(tmp))
        {
            jw_data_free(nsURI);
        }
        if (!node->nsURI)
        {
            return NULL;
        }
    }

    return lookup;
}

static jw_dom_node * _createNode(jw_dom_ctx     *context,
                                 jw_dom_nodetype type,
                                 jw_err         *err)
{
    _jw_dom_nodelist entry;
    jw_dom_node     *node;

    /* allocating the entry also allocates the node */
    if (!jw_pool_calloc(context->pool,
                        1, sizeof(struct _jw_dom_nodelist_t),
                        (void *)&entry, err))
    {
        return NULL;
    }

    /* setup node basics */
    node          = &(entry->data);
    node->context = context;
    node->type    = type;

    /* add to context-wide list */
    if (context->nodes)
    {
        entry->next = context->nodes;
    }
    context->nodes = entry;

    return node;
}

static jw_dom_node * _duplicateNode(jw_dom_ctx  *context,
                                    jw_dom_node *node,
                                    bool         deep,
                                    jw_err      *err)
{
    jw_dom_node *root, *curr, *prev, *idx;

    root = curr = _createNode(context, node->type, err);
    if (!curr)
    {
        return NULL;
    }

    if (node->ename)
    {
        curr->ename = _internString(context,
                                    node->ename,
                                    true,
                                    err);
        if (!curr->ename)
        {
            return false;
        }
        if (node->lname)
        {
            curr->lname = _internString(context,
                                        node->lname,
                                        true,
                                        err);
            if (!curr->lname)
            {
                return false;
            }
        }
        if (node->nsURI)
        {
            curr->nsURI = _internString(context,
                                        node->nsURI,
                                        true,
                                        err);
            if (!curr->nsURI)
            {
                return false;
            }
        }
    }
    if (node->value)
    {
        if (!jw_pool_strdup(context->pool,
                            node->value,
                            (char **)&(curr->value),
                            err))
        {
            return false;
        }
    }

    prev = curr = NULL;
    for (idx = node->nss; idx != NULL; idx = idx->siblingNext)
    {
        curr = _duplicateNode(context, idx, false, err);
        if (!curr)
        {
            return false;
        }

        _attachNode(curr, prev);
        curr->parent = root;
        if (!root->nss)
        {
            root->nss = curr;
        }

        prev = curr;
    }

    prev = curr = NULL;
    for (idx = node->attrs; idx != NULL; idx = idx->siblingNext)
    {
        curr = _duplicateNode(context, idx, false, err);
        if (!curr)
        {
            return false;
        }

        _attachNode(curr, prev);
        curr->parent = root;
        if (!root->attrs)
        {
            root->attrs = curr;
        }

        prev = curr;
    }

    if (deep)
    {
        prev = curr = NULL;
        for (idx = node->childrenFirst; idx != NULL; idx = idx->siblingNext)
        {
            curr = _duplicateNode(context, idx, deep, err);
            if (!curr)
            {
                return false;
            }

            _attachNode(curr, prev);
            curr->parent = root;
            if (!root->childrenFirst)
            {
                root->childrenFirst = curr;
            }
            if (!idx->siblingNext)
            {
                root->childrenLast = curr;
            }

            prev = curr;
        }
    }

    return root;
}

static void _detachNode(jw_dom_node *node)
{
    jw_dom_node *prev = node->siblingPrev;
    jw_dom_node *next = node->siblingNext;

    if (prev)
    {
        prev->siblingNext = next;
    }
    if (next)
    {
        next->siblingPrev = prev;
    }
    node->parent = NULL;
}

static void _attachNode(jw_dom_node *node, jw_dom_node *prev)
{
    jw_dom_node *next = NULL;

    node->siblingPrev = prev;
    if (prev)
    {
        next = prev->siblingNext;
        prev->siblingNext = node;
    }
    if (next)
    {
        next->siblingPrev = node;
    }
    node->siblingNext = next;
}

static void _clearNodes(jw_dom_node *node)
{
    while (node != NULL)
    {
        node->parent = NULL;
        node = node->siblingNext;
    }
}

/**
 * External Functions
 */
 /* context specific */
JABBERWERX_API bool jw_dom_context_create(jw_dom_ctx **ctx, jw_err *err)
{
    assert(ctx != NULL);

    jw_pool    *pool;
    jw_dom_ctx *context;

    if (!jw_pool_create(DOM_CONTEXT_POOL_SIZE, &pool, err))
    {
        return false;
    }

    if (!jw_pool_calloc(
            pool, 1, sizeof(struct _jw_dom_ctx), (void *)&context, err))
    {
        jw_pool_destroy(pool);
        return false;
    }
    context->pool = pool;

    if (!jw_htable_create(DOM_CONTEXT_BUCKET_SIZE,
                          jw_str_hashcode,
                          _intern_str_cmp,
                          &context->strings,
                          err))
    {
        jw_pool_destroy(pool);
        return false;
    }

    context->nodes = NULL;
    context->refCount = 1;

#ifdef DEBUG_REFCOUNT
    if (g_all_contexts)
    {
        g_all_contexts->next = context;
    }
    context->prev = g_all_contexts;
    context->next = NULL;
    g_all_contexts = context;

    context->createStackSize = backtrace(context->createStack, KEEP_STACK);
#endif // DEBUG_REFCOUNT

    jw_log(JW_LOG_DEBUG, "creating dom context %p", (void *)context);

    *ctx = context;
    return true;
}

JABBERWERX_API void jw_dom_context_destroy(jw_dom_ctx *ctx)
{
    assert(ctx != NULL);
    assert(0 < ctx->refCount);

    --ctx->refCount;

    if (0 == ctx->refCount)
    {
        jw_log(JW_LOG_DEBUG,
               "dom context %p refcount reached 0; destroying", (void *)ctx);

#ifdef DEBUG_REFCOUNT
        if (ctx->prev)
        {
            ctx->prev->next = ctx->next;
        }
        if (ctx->next)
        {
            ctx->next->prev = ctx->prev;
            ctx->next = NULL;
        }
        else
        {
            assert(g_all_contexts == ctx);
            g_all_contexts = ctx->prev;
        }
        ctx->prev = NULL;
#endif // DEBUG_REFCOUNT

        /* all strings in memory pool ; don't need to free them separately */
        jw_htable_destroy(ctx->strings);
        /* the context is is the pool; don't need to free it separately */
        jw_pool_destroy(ctx->pool);
    }
    else
    {
        jw_log(JW_LOG_DEBUG,
               "%d reference(s) outstanding on dom context %p; not destroying",
                ctx->refCount, (void *)ctx);
    }
}

#ifdef DEBUG_REFCOUNT
static void debug_node(jw_dom_node *dom)
{
    switch (dom->type)
    {
    case JW_DOM_TYPE_ATTRIBUTE:
        jw_log(JW_LOG_ERROR, "  Attr: %s=%s", dom->ename, dom->value);
        break;
    case JW_DOM_TYPE_NAMESPACE:
        jw_log(JW_LOG_ERROR, "  NS: %s", dom->value);
        break;
    case JW_DOM_TYPE_TEXT:
        jw_log(JW_LOG_ERROR, "  Text: %s", dom->value);
        break;
    case JW_DOM_TYPE_ELEMENT:
        jw_log(JW_LOG_ERROR, "  Elem: %s", dom->ename);
        break;
    }
}
#endif // DEBUG_REFCOUNT

JABBERWERX_API bool jw_dom_contexts_are_all_free(jw_err *err)
#ifdef DEBUG_REFCOUNT
{
    jw_dom_ctx *ctx;
    struct _jw_dom_nodelist_t *node;
    size_t c_count = 0;
    size_t n_count = 0;
    char **syms;
    int i;

    for (ctx=g_all_contexts; ctx; ctx=ctx->prev)
    {
        c_count++;
        jw_log(JW_LOG_ERROR,
               "%d reference(s) outstanding on dom context %p",
                ctx->refCount, ctx);
        syms = backtrace_symbols(ctx->createStack, ctx->createStackSize);
        for (i=0; i<ctx->createStackSize; i++)
        {
            jw_log(JW_LOG_ERROR,
                   "  %s",
                   syms[i]);
        }
        free(syms);
        for (node=ctx->nodes; node; node=node->next)
        {
            n_count++;
            debug_node(&node->data);
        }
    }
    if (g_all_contexts)
    {
        jw_log(JW_LOG_ERROR,
               "%d context(s) with %d total node(s) leaked",
                c_count, n_count);
        JABBERWERX_ERROR(err, JW_ERR_INVALID_STATE);
        return false;
    }
    return true;
}
#else
{
    UNUSED_PARAM(err);
    return true;
}
#endif

JABBERWERX_API bool jw_dom_context_retain(jw_dom_ctx *ctx, jw_err *err)
{
    assert(ctx != NULL);

    // protect against overflow
    if (INT32_MAX == ctx->refCount)
    {
        jw_log(JW_LOG_ERROR, "maximum ref count reached (%d)", INT32_MAX);
        JABBERWERX_ERROR(err, JW_ERR_OVERFLOW);
        return false;
    }

    ++ctx->refCount;

    jw_log(JW_LOG_DEBUG, "dom context %p now has %d references",
           (void *)ctx, ctx->refCount);

    return true;
}

JABBERWERX_API int32_t jw_dom_context_get_refcount_DEBUG(jw_dom_ctx *ctx)
{
    assert(ctx != NULL);
    return ctx->refCount;
}

JABBERWERX_API jw_pool * jw_dom_context_get_pool(jw_dom_ctx *ctx)
{
    assert(ctx != NULL);
    return ctx->pool;
}

/* import/copy */
JABBERWERX_API bool jw_dom_import(jw_dom_ctx   *ctx,
                                  jw_dom_node  *node,
                                  bool          deep,
                                  jw_dom_node **cpy,
                                  jw_err       *err)
{
    JW_LOG_TRACE_FUNCTION("node=%p; deep=%d", (void *)node, deep);

    jw_dom_node *n;

    assert(ctx != NULL);
    assert(node != NULL);
    assert(cpy != NULL);

    if (jw_dom_get_context(node) == ctx)
    {
        *cpy = node;
        return true;
    }

    n = _duplicateNode(ctx, node, deep, err);
    if (!n)
    {
        return false;
    }

    *cpy = n;
    return true;
}

JABBERWERX_API bool jw_dom_clone(jw_dom_node  *node,
                                 bool          deep,
                                 jw_dom_node **cpy,
                                 jw_err       *err)
{
    JW_LOG_TRACE_FUNCTION("node=%p; deep=%d", (void *)node, deep);

    jw_dom_node *orig, *n;

    assert(node != NULL);
    assert(cpy != NULL);

    orig = node;
    n = _duplicateNode(orig->context, orig, deep, err);
    if (!n)
    {
        return false;
    }

    *cpy = n;
    return true;
}

/* creation */
static bool _jw_dom_element_create(jw_dom_ctx      *ctx,
                                   const char      *ename,
                                   jw_dom_node    **elem,
                                   _validateENameFn validateENameFn,
                                   jw_err          *err)
{
    JW_LOG_TRACE_FUNCTION("ename='%s'", ename);

    jw_dom_node *n;

    assert(ctx != NULL);
    assert(ename != NULL);
    assert(elem != NULL);

    /* allocating the entry also allocates the node */
    n = _createNode(ctx, JW_DOM_TYPE_ELEMENT, err);
    if (!n)
    {
        /* error info already populated */
        return false;
    }

    ename = _internEName(n, ename, DOM_ENAME_FULL, validateENameFn, err);
    if (!ename)
    {
        /* error info already populated */
        return false;
    }

    *elem = n;

    return true;
}

JABBERWERX_API bool jw_dom_element_create(jw_dom_ctx   *ctx,
                                          const char   *ename,
                                          jw_dom_node **elem,
                                          jw_err       *err)
{
    return _jw_dom_element_create(ctx, ename, elem, _validateEName, err);
}

bool jw_dom_element_create_int(jw_dom_ctx   *ctx,
                               const char   *ename,
                               jw_dom_node **elem,
                               jw_err       *err)
{
    return _jw_dom_element_create(ctx, ename, elem, _noValidateEName, err);
}

static bool _jw_dom_text_create(jw_dom_ctx     *ctx,
                                const char     *value,
                                jw_dom_node   **text,
                                _validateUTF8Fn validateUTF8Fn,
                                jw_err         *err)
{
    JW_LOG_TRACE_FUNCTION("value='%s'", value);

    jw_dom_node *n;
    char        *dup;

    assert(ctx != NULL);
    assert(value != NULL);
    assert(text != NULL);

    if (value[0] == '\0' || !validateUTF8Fn(value))
    {
        JABBERWERX_ERROR(err, JW_ERR_INVALID_ARG);
        return false;
    }

    /* allocating the entry also allocates the node */
    n = _createNode(ctx, JW_DOM_TYPE_TEXT, err);
    if (!n)
    {
        return false;
    }
    if (!jw_pool_strdup(ctx->pool, value, &dup, err))
    {
        return false;
    }
    n->value = dup;
    *text = n;

    return true;
}

JABBERWERX_API bool jw_dom_text_create(jw_dom_ctx   *ctx,
                                       const char   *value,
                                       jw_dom_node **text,
                                       jw_err       *err)
{
    return _jw_dom_text_create(ctx, value, text, _validateUTF8, err);
}

bool jw_dom_text_create_int(jw_dom_ctx   *ctx,
                            const char   *value,
                            jw_dom_node **text,
                            jw_err       *err)
{
    return _jw_dom_text_create(ctx, value, text, _noValidateUTF8, err);
}

/* node-generic basics */
JABBERWERX_API jw_dom_ctx *jw_dom_get_context(jw_dom_node *node)
{
    assert(node != NULL);
    return node->context;
}

JABBERWERX_API jw_dom_nodetype jw_dom_get_nodetype(jw_dom_node *node)
{
    assert(node != NULL);
    return node->type;
}

JABBERWERX_API const char * jw_dom_get_ename(jw_dom_node *node)
{
    assert(node != NULL);
    return node->ename;
}

JABBERWERX_API const char * jw_dom_get_localname(jw_dom_node *node)
{
#ifndef NDEBUG
    jw_dom_nodetype type = jw_dom_get_nodetype(node);
    assert((type == JW_DOM_TYPE_ELEMENT) ||
           (type == JW_DOM_TYPE_ATTRIBUTE));
#endif

    return node->lname;
}

JABBERWERX_API const char * jw_dom_get_namespace_uri(jw_dom_node *node)
{
#ifndef NDEBUG
    jw_dom_nodetype type = jw_dom_get_nodetype(node);
    assert((type == JW_DOM_TYPE_ELEMENT) ||
           (type == JW_DOM_TYPE_ATTRIBUTE));
#endif
    return node->nsURI;
}

JABBERWERX_API const char * jw_dom_get_value(jw_dom_node *node)
{
    assert(node != NULL);

    return node->value;
}

/* node-generic hierarchy */
JABBERWERX_API jw_dom_node * jw_dom_get_parent(jw_dom_node *node)
{
    assert(node != NULL);

    return node->parent;
}

JABBERWERX_API jw_dom_node * jw_dom_get_sibling(jw_dom_node *node)
{
    assert(node != NULL);

    return node->siblingNext;
}

JABBERWERX_API void jw_dom_detach(jw_dom_node *node)
{
    JW_LOG_TRACE_FUNCTION("node=%p", (void *)node);

    jw_dom_node *n, *pn;

    assert(node != NULL);
    n = node;
    pn = n->parent;
    if (pn != NULL)
    {
        jw_dom_node *rep;
        if (n->siblingPrev)
        {
            rep = n->siblingPrev;
        }
        else
        {
            rep = n->siblingNext;
        }
        _detachNode(n);

        if (n == pn->attrs)
        {
            pn->attrs = rep;
        }
        else if (n == pn->nss)
        {
            pn->nss = rep;
        }
        else
        {
            if (pn->childrenFirst == n)
            {
                pn->childrenFirst = rep;
            }
            if (pn->childrenLast == n)
            {
                pn->childrenLast = rep;
            }
        }
    }

}

/* element specific: namespaces */
JABBERWERX_API jw_dom_node * jw_dom_get_first_namespace(jw_dom_node *elem)
{
    assert(jw_dom_get_nodetype(elem) == JW_DOM_TYPE_ELEMENT);
    return elem->nss;
}

static bool _jw_dom_put_namespace(jw_dom_node     *elem,
                                  const char      *prefix,
                                  const char      *uri,
                                  _validateENameFn validateENameFn,
                                  jw_err          *err)
{
    JW_LOG_TRACE_FUNCTION("elem=%p; prefix='%s'; uri='%s'",
                          (void *)elem, prefix, uri);

    jw_dom_node *en, *prev, *nn;
    jw_dom_ctx  *ctx;
    jw_pool     *pool;

    assert(prefix);
    en = elem;
    nn = jw_dom_get_first_namespace(elem);
    prev = NULL;

    ctx = en->context;
    pool = ctx->pool;
    while (nn != NULL)
    {
        if (_intern_str_cmp(prefix, nn->ename) == 0)
        {
            /* namespace exists, so modify... */
            if (!uri)
            {
                /* ...or remove namespace */
                jw_dom_detach(nn);
            }

            if (jw_pool_strdup(pool, uri, (char **)&(nn->value), err))
            {
                return true;
            }

            return false;
        }

        prev = nn;
        nn = nn->siblingNext;
    }

    if (uri)
    {
        /* doesn't exist, so create */
        /* validate prefix does not start with xml, unless...
            1) it *IS* "xml", and
            2) the url is "http://www.w3.org/XML/1998/namespace" */
        if (strncasecmp(prefix, "xml", 3) == 0)
        {
            if (strncmp(prefix, "xml", 3) != 0 ||
                strcmp(uri, "http://www.w3.org/XML/1998/namespace") != 0)
            {
                JABBERWERX_ERROR(err, JW_ERR_INVALID_ARG);
                return false;
            }
        }

        nn = _createNode(ctx, JW_DOM_TYPE_NAMESPACE, err);
        if (!nn)
        {
            return false;
        }

        prefix = _internEName(nn,
                              prefix,
                              DOM_ENAME_LOCALNAME | DOM_ENAME_OPTIONAL,
                              validateENameFn,
                              err);
        if (!prefix)
        {
            return false;
        }

        /* \todo add uri to strings table? */
        if (!jw_pool_strdup(pool, uri, (char **)&uri, err))
        {
            return false;
        }

        nn->parent = en;
        nn->value = uri;

        _attachNode(nn, prev);
        if (!prev)
        {
            /* first namespace */
            en->nss = nn;
        }
    }

    return true;
}

JABBERWERX_API bool jw_dom_put_namespace(jw_dom_node *elem,
                                         const char  *prefix,
                                         const char  *uri,
                                         jw_err      *err)
{
    return _jw_dom_put_namespace(elem, prefix, uri, _validateEName, err);
}

bool jw_dom_put_namespace_int(jw_dom_node *elem,
                              const char  *prefix,
                              const char  *uri,
                              jw_err      *err)
{
    return _jw_dom_put_namespace(elem, prefix, uri, _noValidateEName, err);
}

JABBERWERX_API const char * jw_dom_find_namespace_uri(jw_dom_node *elem,
                                                      const char  *prefix)
{
    jw_dom_node *en = elem;
    jw_dom_node *nn = jw_dom_get_first_namespace(elem);

    assert(prefix);
    while (nn != NULL)
    {
        if (_intern_str_cmp(prefix, nn->ename) == 0)
        {
            return nn->value;
        }

        nn = nn->siblingNext;
    }

    if (en->parent)
    {
        return jw_dom_find_namespace_uri(en->parent, prefix);
    }

    return NULL;
}

JABBERWERX_API const char * jw_dom_find_namespace_prefix(jw_dom_node *elem,
                                                         const char  *uri)
{
    jw_dom_node *en = elem;
    jw_dom_node *nn = jw_dom_get_first_namespace(elem);

    assert(uri);
    while (nn != NULL)
    {
        if (_intern_str_cmp(uri, nn->value) == 0)
        {
            return nn->ename;
        }

        nn = nn->siblingNext;
    }

    if (en->parent)
    {
        return jw_dom_find_namespace_prefix(en->parent, uri);
    }

    return NULL;
}

/* element specific: attributes */
JABBERWERX_API jw_dom_node * jw_dom_get_first_attribute(jw_dom_node *elem)
{
    /** getting the nodetype will also check elem != NULL */
    assert(jw_dom_get_nodetype(elem) == JW_DOM_TYPE_ELEMENT);

    return elem->attrs;
}

JABBERWERX_API const char * jw_dom_get_attribute(jw_dom_node *elem,
                                                 const char  *ename)
{
    jw_dom_node *an = jw_dom_get_first_attribute(elem);
    const char  *value = NULL;

    assert(ename);
    while (value == NULL && an != NULL)
    {
        if (_compareEName(ename, an->ename, true))
        {
            value = an->value;
        }
        an = an->siblingNext;
    }

    return value;
}

static bool _jw_dom_set_attribute(jw_dom_node     *elem,
                                  const char      *ename,
                                  const char      *value,
                                  _validateUTF8Fn  validateUTF8Fn,
                                  _validateENameFn validateENameFn,
                                  jw_err          *err)
{
    JW_LOG_TRACE_FUNCTION("elem=%p; ename='%s'; value='%s'",
                          (void *)elem, ename, value);

    jw_dom_node *en, *prev, *an;
    jw_dom_ctx  *ctx;
    jw_pool     *pool;

    assert(ename);
    en = elem;
    an = jw_dom_get_first_attribute(elem);
    prev = NULL;

    ctx = en->context;
    pool = ctx->pool;
    while (an != NULL)
    {
        if (_intern_str_cmp(ename, an->ename) == 0)
        {
            /* attribute exists, so modify... */
            if (!value)
            {
                /* ...or remove attribute */
                jw_dom_detach(an);
            }

            if (jw_pool_strdup(pool, value, (char **)&(an->value), err))
            {
                return true;
            }

            return false;
        }

        prev = an;
        an = an->siblingNext;
    }

    if (value)
    {
        /* doesn't exist, so create */
        if (!validateUTF8Fn(value))
        {
            JABBERWERX_ERROR(err, JW_ERR_INVALID_ARG);
            return false;
        }
        an = _createNode(ctx, JW_DOM_TYPE_ATTRIBUTE, err);
        if (!an)
        {
            return false;
        }

        ename = _internEName(an, ename, DOM_ENAME_FULL, validateENameFn, err);
        if (!ename)
        {
            return false;
        }
        /* \todo add value to strings table? */
        if (!jw_pool_strdup(pool, value, (char **)&value, err))
        {
            return false;
        }

        an->parent = en;
        an->value = value;

        _attachNode(an, prev);
        if (!prev)
        {
            /* first attribute */
            en->attrs = an;
        }
    }

    return true;
}

JABBERWERX_API bool jw_dom_set_attribute(jw_dom_node *elem,
                                         const char  *ename,
                                         const char  *value,
                                         jw_err      *err)
{
    return _jw_dom_set_attribute(
            elem, ename, value, _validateUTF8, _validateEName, err);
}

bool jw_dom_set_attribute_int(jw_dom_node *elem,
                              const char *ename,
                              const char *value,
                              jw_err *err)
{
    return _jw_dom_set_attribute(
            elem, ename, value, _noValidateUTF8, _noValidateEName, err);
}

JABBERWERX_API jw_dom_node * jw_dom_get_first_child(jw_dom_node *elem)
{
    assert(jw_dom_get_nodetype(elem) == JW_DOM_TYPE_ELEMENT);
    return elem->childrenFirst;
}

JABBERWERX_API jw_dom_node * jw_dom_get_first_element(jw_dom_node *elem,
                                                      const char  *ename)
{
    jw_dom_node *cn;

    assert(jw_dom_get_nodetype(elem) == JW_DOM_TYPE_ELEMENT);
    for (cn = jw_dom_get_first_child(elem);
         cn != NULL;
         cn = cn->siblingNext)
    {
        if (cn->type != JW_DOM_TYPE_ELEMENT)
        {
            continue;
        }
        if (ename && !_compareEName(ename, cn->ename, false))
        {
            continue;
        }

        return cn;
    }

    return NULL;
}

JABBERWERX_API const char * jw_dom_get_first_text(jw_dom_node *elem)
{
    jw_dom_node *cn;

    assert(jw_dom_get_nodetype(elem) == JW_DOM_TYPE_ELEMENT);
    for(cn = jw_dom_get_first_child(elem);
        cn != NULL;
        cn = cn->siblingNext)
    {
        if (cn->type != JW_DOM_TYPE_TEXT)
        {
            continue;
        }

        return cn->value;
    }

    return NULL;
}

JABBERWERX_API bool jw_dom_add_child(jw_dom_node *parent,
                                     jw_dom_node *child,
                                     jw_err      *err)
{
    JW_LOG_TRACE_FUNCTION("parent=%p; child=%p", (void *)parent, (void *)child);

    jw_dom_node    *ancestor, *pn, *cn;
#ifndef NDEBUG
    jw_dom_nodetype type = jw_dom_get_nodetype(parent);
    assert(type == JW_DOM_TYPE_ELEMENT);
    type = jw_dom_get_nodetype(child);
    assert((type == JW_DOM_TYPE_ELEMENT) || (type == JW_DOM_TYPE_TEXT));
#endif
    assert(jw_dom_get_context(parent) == jw_dom_get_context(child));

    ancestor = pn = parent;
    cn = child;

    while (ancestor != NULL)
    {
        if (ancestor == cn)
        {
            JABBERWERX_ERROR(err, JW_ERR_INVALID_ARG);
            return false;
        }

        ancestor = ancestor->parent;
    }

    jw_dom_detach(child);
    if (!pn->childrenFirst)
    {
        pn->childrenFirst = cn;
    }
    else
    {
        _attachNode(cn, pn->childrenLast);
    }
    pn->childrenLast = cn;
    cn->parent = pn;

    return true;
}

JABBERWERX_API bool jw_dom_remove_child(jw_dom_node *parent,
                                        jw_dom_node *child,
                                        jw_err      *err)
{
    JW_LOG_TRACE_FUNCTION("parent=%p; child=%p", (void *)parent, (void *)child);

    assert(jw_dom_get_nodetype(parent) == JW_DOM_TYPE_ELEMENT);
    assert(child != NULL);

    if (parent == child)
    {
        JABBERWERX_ERROR(err, JW_ERR_INVALID_ARG);
        return false;
    }
    if (jw_dom_get_parent(child) != parent)
    {
        JABBERWERX_ERROR(err, JW_ERR_INVALID_ARG);
        return false;
    }

    jw_dom_detach(child);

    return true;
}

JABBERWERX_API void jw_dom_clear_children(jw_dom_node *elem)
{
    JW_LOG_TRACE_FUNCTION("elem=%p", (void *)elem);

    jw_dom_node *en;

    assert(elem != NULL);
    en = elem;
    _clearNodes(en->childrenFirst);
    en->childrenFirst = en->childrenLast = NULL;
}
