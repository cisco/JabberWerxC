/**
 * \file
 * \brief
 * Functions for simplified logging
 *
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

#ifndef JABBERWERX_UTIL_LOG_H
#define JABBERWERX_UTIL_LOG_H

#include <stdarg.h>
#include <stdio.h>
#include "../dom.h"
#include "mem.h"


/** Convenience macro for tracing a function entry where no arguments need to be
 *  logged */
#define JW_LOG_TRACE_FUNCTION_NO_ARGS \
        jw_log(JW_LOG_TRACE, "entering: %s", __func__)
/** Convenience macro for tracing a function entry with logged arguments.
 * The space after __func__ but before the comma is intentional as recommended
 * at http://gcc.gnu.org/onlinedocs/cpp/Variadic-Macros.html for compatibility
 */
#define JW_LOG_TRACE_FUNCTION(fmt, ...) \
        jw_log(JW_LOG_TRACE, "entering: %s; args=("fmt")", \
        __func__ , __VA_ARGS__)

/**
 * Macro to log an element, its context and reference. Restrictions detailed in
 * jw_log_dom apply.
 *
 * \param[in] level The log level for this message.
 * \param[in] dom the element to be logged.
 * \param[in] caption string appended to dom information, may be NULL or empty
 */
#define JW_LOG_DOM_REF(level, dom, caption)\
    jw_log_dom((level), (dom), "%s(context: %p, ref: %p)", \
               (caption) ? (caption) : "",\
               (dom) ? (void *)jw_dom_get_context((dom)) : NULL, \
               (void *)(dom));


/**
 * Enumeration of defined log levels
 */
typedef enum
{
    /** Log level that indicates no messages should be output */
    JW_LOG_NONE = 0,
    /** Logging error-level messages */
    JW_LOG_ERROR,
    /** Logging warn-level messages */
    JW_LOG_WARN,
    /** Logging info-level messages */
    JW_LOG_INFO,
    /** Logging verbose-level messages */
    JW_LOG_VERBOSE,
    /** Logging debug-level messages */
    JW_LOG_DEBUG,
    /** Logging trace-level messages */
    JW_LOG_TRACE,
    /** Logging memory allocation-level messages */
    JW_LOG_MEMTRACE
} jw_loglevel;

/**
 * Signature of the log text generator function passed to jw_log_chunked().  No
 * log message functions should be called from this function to avoid garbled
 * output or infinite loops.
 *
 * \invariant chunk != NULL
 * \invariant len != NULL
 * \invariant free_fn != NULL
 * \param[out] chunk A pointer to the fragment to append to the in-progress log
 *      message.  The function will be called repeatedly until *chunk is set to
 *      NULL.  If *len is not set or explicitly set to 0, *chunk is assumed to
 *      be a NULL-terminated string.
 * \param[out] len A pointer to the length of the fragment pointed to by chunk.
 *      If *chunk is NULL-terminated, this variable does not need to be set.
 * \param[out] free_fn A pointer to the function that will be called to free
 *      *chunk.  If *chunk does not need freeing, *free_fn does not need to be
 *      set.
 * \param[in] arg The user-supplied pointer passed to jw_log_chunked().
 */
typedef void (*jw_log_generator_fn)(
        const char **chunk, size_t *len, jw_data_free_func *free_fn, void *arg);


#ifdef __cplusplus
extern "C"
{
#endif

/**
 * Retrieve the string version of the jw_loglevel enum.
 *
 * \param level The log level to lookup
 * \retval const char * The message for {level}
 */
JABBERWERX_API const char *jw_log_level_name(jw_loglevel level);

/**
 * Function like vfprintf to be used for logging.
 *
 * Note: Supplied function will be called three times for each log
 * message; once for date/time/level preamble, once for the message and
 * once for a trailing newline.
 *
 * \param stream Output stream, always stderr.
 * \param format Format string like vfprintf.
 * \param ap Additional parameters to interpolate into {fmt}.
 * \retval Number of bytes written.
 */
typedef int (*jw_log_vararg_function)(
                FILE *stream, const char *format, va_list ap);

/**
 * Set the logging function.
 *
 * Log function defaults to vfprintf. A null parameter resets the
 * log function to its default.
 *
 * Note: Not thread-safe.
 *
 * \param fn The vfprintf-like function to use.
 */
JABBERWERX_API void jw_log_set_function(jw_log_vararg_function fn);

/**
 * Set the current log level, defaults to JW_LOG_INFO.
 *
 * Everything at this level or less verbose than this level will be printed.
 *
 * Note: Not thread-safe.
 *
 * \param level The new log level.
 */
JABBERWERX_API void jw_log_set_level(jw_loglevel level);

/**
 * Get the current log level.
 *
 * \retval The current log level.
 */
JABBERWERX_API jw_loglevel jw_log_get_level();

/**
 * Enables or disables printing the NDC prefix for log messages.  By default,
 * the NDC prefix is enabled.
 * 
 * \param[in] enabled true if the NDC should be output; otherwise false.
 */
JABBERWERX_API void jw_log_set_ndc_enabled(bool enabled);

/**
 * Pushes a nested diagnostic context onto the NDC stack.  The given message
 * will be prefixed to all subsequent messages until a corresponding call to
 * jw_log_pop_ndc() is made.
 *
 * \invariant fmt != NULL
 * \param[in] fmt The printf-style format string
 * \param[in] ... Extra parameters to interpolate into {fmt}.
 * @return The depth of the NDC stack after the given push.  This must later
 * be passed to jw_log_pop_ndc() to verify the consistency of the NDC stack.  If
 * this function fails to push (due, for example, to a low memory condition or
 * a malformed format string), an appropriate warning will be printed and 0
 * will be returned.
 */
JABBERWERX_API int jw_log_push_ndc(const char *fmt, ...)
        __attribute__ ((__format__ (__printf__, 1, 2)));

/**
 * Pops a nested diagnostic context from the NDC stack.
 *
 * @param ndc_depth The value returned from jw_log_push_ndc().  If this value
 * does not match the current NDC stack depth, a warning will be logged and
 * the stack will be reduced to the expected depth.  If 0 is passed in, this
 * function is a noop.
 */
JABBERWERX_API void jw_log_pop_ndc(int ndc_depth);

/**
 * Log at the given level to stderr.
 *
 * All errors while logging are ignored (so this routine is not
 * guaranteed to log).  Extra parameters are injected into {fmt}
 * using the rules from vfprintf.
 *
 * Log messages are prepended with date/time and log level and
 * appended with a newline; YYYY-MM-DDTHH-MM-SS[level]: {fmt}\n
 *
 * Note: Not thread-safe with respect to the current log level.
 *
 * \invariant fmt != NULL
 * \param[in] level The log level for this message.  Note that JW_LOG_NONE is
 *                  not a valid log level to pass to this function.
 * \param[in] fmt The printf-style format to log
 * \param[in] ... Extra parameters to interpolate into {fmt}.
 */
JABBERWERX_API void jw_log(jw_loglevel level, const char *fmt, ...)
        __attribute__ ((__format__ (__printf__, 2, 3)));

/**
 * Log an error, with extra information.  If the error is NULL,
 * just use the extra information.
 *
 * Note: Not thread-safe with respect to the current log level.
 *
 * \invariant fmt != NULL
 * \param[in] level The log level for this message.  Note that JW_LOG_NONE is
 *                  not a valid log level to pass to this function.
 * \param[in] err The error to be printed (if not NULL).
 * \param[in] fmt The printf-style format to log
 * \param[in] ... Extra parameters to interpolate into {fmt}.
 */
JABBERWERX_API void jw_log_err(jw_loglevel level, jw_err *err,
        const char *fmt, ...) __attribute__ ((__format__ (__printf__, 3, 4)));

/**
 * Log a jw_dom_node element with extra information.
 * dom and fmt may be NULL. Logs message "fmt(&lt;serialized dom/&gt;|(null))\n"
 *
 * Note: Not thread-safe with respect to the current log level.
 * Note: Resources are allocated and freed within this function. Failures
 *       are reported as "dom could not be serialized" in the log message.
 *
 * \param[in] level The log level for this message.  Note that JW_LOG_NONE is
 *                  not a valid log level to pass to this function.
 * \param[in] dom The element to be logged.  May be NULL.  If the dom is not an
 *                element, "dom could not be serialized" will be output.
 * \param[in] fmt The printf-style format to log.  If NULL, equivalent to "".
 * \param[in] ... Extra parameters to interpolate into {fmt}.
 */
JABBERWERX_API void jw_log_dom(jw_loglevel level, jw_dom_node *dom,
        const char *fmt, ...) __attribute__ ((__format__ (__printf__, 3, 4)));

/**
 * Log a message with content provided by a generator function.  The content
 * from the generator function will appear immediately after the specified fmt,
 * i.e.: "fmt&lt;generator fn output&gt;\n"
 *
 * Note: Not thread-safe with respect to the current log level.
 *
 * \param[in] level The log level for this message.  Note that JW_LOG_NONE is
 *                  not a valid log level to pass to this function.
 * \param[in] generator_fn The generator function that will provide the log
 *                message content.
 * \param[in] arg The opaque pointer passed to the generator function.
 * \param[in] fmt The printf-style format to log.  If NULL, equivalent to "".
 * \param[in] ... Extra parameters to interpolate into {fmt}.
 */
JABBERWERX_API void jw_log_chunked(jw_loglevel level,
        jw_log_generator_fn generator_fn, void *arg,
        const char *fmt, ...) __attribute__ ((__format__ (__printf__, 4, 5)));

#ifdef __cplusplus
}
#endif

#endif  /* JABBERWERX_UTIL_LOG_H */
