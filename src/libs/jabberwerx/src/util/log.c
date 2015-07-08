/**
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

#include "../include/log_int.h"
#include <jabberwerx/util/log.h>
#include <jabberwerx/util/mem.h>
#include <jabberwerx/util/serializer.h>

#include <time.h>
#include <string.h>
#include <assert.h>

/*****************************************************************************
 * Internal type definitions
 */

static const char *_LOG_MSG_TABLE[] = {
    "NONE",
    "ERROR",
    "WARN",
    "INFO",
    "VERBOSE",
    "DEBUG",
    "TRACE",
    "MEMTRACE"
};
static jw_loglevel _jw_loglevel = JW_LOG_INFO;
static jw_log_vararg_function _jw_log_vararg_function = vfprintf;
static jw_data_malloc_func _allocator = jw_data_malloc;
static jw_data_free_func _deallocator = jw_data_free;

typedef struct _ndc_node_int_t
{
    uint32_t               id;
    char                   *message;
    struct _ndc_node_int_t *next;
} *_ndc_node_t;

static bool        _ndc_enabled = true;
// TODO: once we support threading, these will have to be thread-local instead
// TODO:   of static
static int         _ndc_depth = 0;
static _ndc_node_t _ndc_head  = NULL;
static uint32_t    _ndc_count = 0;


static int _jw_log_fixed_function(FILE *stream, const char *fmt, ...)
        __attribute__ ((__format__ (__printf__, 2, 3)));
static int _jw_log_fixed_function(FILE *stream, const char *fmt, ...)
{
    va_list ap;
    int ret;

    va_start(ap, fmt);
    ret = _jw_log_vararg_function(stream, fmt, ap);
    va_end(ap);

    return ret;
}

JABBERWERX_API const char * jw_log_level_name(jw_loglevel level)
{
    assert(JW_LOG_NONE <= (int)level);
    assert(JW_LOG_MEMTRACE >= level);

    return _LOG_MSG_TABLE[level];
}

void _jw_log_set_memory_funcs(jw_data_malloc_func allocator,
                              jw_data_free_func   deallocator)
{
    if (!allocator)
    {
        _allocator = jw_data_malloc;
    }
    else
    {
        _allocator = allocator;
    }

    if (!deallocator)
    {
        _deallocator = jw_data_free;
    }
    else
    {
        _deallocator = deallocator;
    }
}

JABBERWERX_API void jw_log_set_function(jw_log_vararg_function fn)
{
    if (!fn)
    {
        _jw_log_vararg_function = vfprintf;
    }
    else
    {
        _jw_log_vararg_function = fn;
    }
}

JABBERWERX_API void jw_log_set_level(jw_loglevel level)
{
    assert(JW_LOG_NONE <= (int)level);
    assert(JW_LOG_MEMTRACE >= level);

    _jw_loglevel = level;
}

JABBERWERX_API void jw_log_set_ndc_enabled(bool enabled)
{
    _ndc_enabled = enabled;
}

JABBERWERX_API jw_loglevel jw_log_get_level()
{
    return _jw_loglevel;
}

static void _log_ndc_stack(_ndc_node_t ndcNode)
{
    if (!ndcNode)
    {
        return;
    }

    if (ndcNode->next)
    {
        _log_ndc_stack(ndcNode->next);
    }

    _jw_log_fixed_function(stderr, "{ndcid=%u; %s} ",
                           ndcNode->id, ndcNode->message);
}

static bool _log_prefix(jw_loglevel level)
{
    time_t t;
    struct tm local;

    assert(JW_LOG_ERROR <= level);
    assert(JW_LOG_MEMTRACE >= level);

    if (level > _jw_loglevel)
    {
       return false;
    }

    // TODO: cache time and update it asyncronously with a timer?
    t = time(NULL);
    if ((t == (time_t)-1) || !localtime_r(&t, &local))
    {
        // Note: both time() and localtime_r() only fail for
        // reasons that are difficult if impossible to create,
        // so don't worry about coverage over this return line.
        return false;
    }

    _jw_log_fixed_function(stderr,
            "%d-%2.2d-%2.2dT%2.2d:%2.2d:%2.2d [%8s]: ",
            local.tm_year+1900,
            local.tm_mon+1,
            local.tm_mday,
            local.tm_hour,
            local.tm_min,
            local.tm_sec,
            jw_log_level_name(level));

    if (_ndc_enabled)
    {
        _log_ndc_stack(_ndc_head);
    }

    return true;
}

JABBERWERX_API int jw_log_push_ndc(const char *fmt, ...)
{
    assert(fmt);

    va_list ap;
    int messageLen;

    va_start(ap, fmt);
    if (0 > (messageLen = vsnprintf(NULL, 0, fmt, ap)))
    {
        jw_log(JW_LOG_WARN,"invalid NDC format string: '%s'", fmt);
        return 0;
    }
    va_end(ap);

    _ndc_node_t newNode = _allocator(sizeof(struct _ndc_node_int_t));
    if (!newNode)
    {
        jw_log(JW_LOG_WARN, "could not push NDC: '%s' (out of memory)", fmt);
        return 0;
    }

    memset(newNode, 0, sizeof(struct _ndc_node_int_t));
    newNode->message = _allocator(messageLen+1);
    if (!newNode->message)
    {
        _deallocator(newNode);
        jw_log(JW_LOG_WARN, "could not push NDC: '%s' (out of memory)", fmt);
        return 0;
    }

    va_start(ap, fmt);
    messageLen = vsprintf(newNode->message, fmt, ap);
    assert(0 <= messageLen);
    va_end(ap);

    newNode->id   = _ndc_count++;
    newNode->next = _ndc_head;
    _ndc_head     = newNode;

    return ++_ndc_depth;
}

JABBERWERX_API void jw_log_pop_ndc(int ndc_depth)
{
    assert(0 <= ndc_depth);

    if (0 == ndc_depth)
    {
        return;
    }

    if (ndc_depth != _ndc_depth)
    {
        jw_log(JW_LOG_WARN, "ndc depth mismatch on pop (expected %d, got %d)",
               _ndc_depth, ndc_depth);
    }

    while (_ndc_head && _ndc_depth >= ndc_depth)
    {
        --_ndc_depth;
        _ndc_node_t prevHead = _ndc_head;
        _ndc_head = prevHead->next;

        _deallocator(prevHead->message);
        _deallocator(prevHead);
    }
}

JABBERWERX_API void jw_log(jw_loglevel level, const char *fmt, ...)
{
    va_list ap;

    assert(fmt);

    if (!_log_prefix(level))
    {
        return;
    }

    va_start(ap, fmt);
    _jw_log_vararg_function(stderr, fmt, ap);
    va_end(ap);
    _jw_log_fixed_function(stderr, "\n");
}

JABBERWERX_API void jw_log_err(
        jw_loglevel level, jw_err *err, const char *fmt, ...)
{
    va_list ap;

    assert(fmt);

    if (!_log_prefix(level))
    {
        return;
    }

    if (err && err->message)
    {
        // err->code is almost always useless, since err->message is usually
        // already set with jw_err_message() in the JABBERWERX_ERROR
        // macro.
        _jw_log_fixed_function(stderr, "reason(%s): ", err->message);
    }

    va_start(ap, fmt);
    _jw_log_vararg_function(stderr, fmt, ap);
    va_end(ap);
    _jw_log_fixed_function(stderr, "\n");
}

JABBERWERX_API void jw_log_dom(
        jw_loglevel level, jw_dom_node *dom, const char *fmt, ...)
{
    char       *dstr = NULL;
    const char *ostr = NULL;
    va_list ap;

    // we can't just call _log_prefix here since jw_serialize_xml might output
    // log messages before we can print the rest of this one
    if (level > _jw_loglevel)
    {
       return;
    }

    if (!dom)
    {
        ostr = "(null)";
    }
    else if (JW_DOM_TYPE_TEXT == jw_dom_get_nodetype(dom))
    {
        ostr = jw_dom_get_value(dom);
    }
    else if (JW_DOM_TYPE_ELEMENT != jw_dom_get_nodetype(dom)
          || !jw_serialize_xml(dom, &dstr, NULL, NULL))
    {
        ostr = "dom could not be serialized";
    }
    else
    {
        ostr = dstr;
    }

    if (_log_prefix(level))
    {
        if (fmt)
        {
            va_start(ap, fmt);
            _jw_log_vararg_function(stderr, fmt, ap);
            va_end(ap);
        }

        _jw_log_fixed_function(stderr, "%s\n", ostr ? ostr : "(null)");
    }

    if (dstr)
    {
        jw_data_free(dstr);
    }
}

JABBERWERX_API void jw_log_chunked(jw_loglevel level,
                                   jw_log_generator_fn generator_fn, void *arg,
                                   const char *fmt, ...)
{
    va_list ap;

    assert(generator_fn);
    assert(fmt);

    if (!_log_prefix(level))
    {
        return;
    }

    va_start(ap, fmt);
    _jw_log_vararg_function(stderr, fmt, ap);
    va_end(ap);

    while (true)
    {
        const char       *chunk   = NULL;
        size_t            len     = 0;
        jw_data_free_func free_fn = NULL;

        generator_fn(&chunk, &len, &free_fn, arg);

        if (!chunk)
        {
            break;
        }

        if (0 == len)
        {
            _jw_log_fixed_function(stderr, "%s", chunk);
        }
        else
        {
            _jw_log_fixed_function(stderr, "%.*s", (int)len, chunk);
        }

        if (free_fn)
        {
            free_fn((char *)chunk);
        }
    }

    _jw_log_fixed_function(stderr, "\n");
}
