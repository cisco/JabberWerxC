/**
 * \file
 * \brief
 * Basic defines, macros, and global functions for JabberWerxC.
 *
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

#ifndef JABBERWERX_BASICS_H
#define JABBERWERX_BASICS_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>


/**
 * \def JABBERWERX_API
 * Marks a symbol as part of the public API.
 */
#if defined(_WIN32) || defined(_WIN64)
#  ifdef jabberwerx_EXPORTS
#    define JABBERWERX_API __declspec(dllexport)
#  else
#    define JABBERWERX_API __declspec(dllimport)
#  endif
#else
#  define JABBERWERX_API
#endif

#ifndef UNUSED_PARAM
  /**
   * \def UNUSED_PARAM(p);
   *
   * A macro for quelling compiler warnings about unused variables.
   */
#  define UNUSED_PARAM(p) ((void)&(p))
#endif // UNUSED_PARAM

#ifndef __GNUC__
   /** Hide GCC attribute definitions from non-GCC compilers */
#  define __attribute__(x)
#endif // __GNUC__
 
/**
 * Compiler pragma helper.
 *
 * Insert a C99 compiler pragma based on an unterminated string.  This allows
 * for pragmas to be generated dynamically.
 */
#define PRAGMA(x) _Pragma(#x)

/*
 * Temporarily disable compiler warnings, if possible (>=gcc-4.6).
 *
 * In some cases (particularly within macros), certain compiler warnings are
 * unavoidable.  In order to allow these warnings to be treated as errors in
 * most cases, these macros will disable particular warnings only during
 * specific points in the compilation.
 */
#if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6)
#  define GCC_BEGIN_IGNORED_WARNING(x) \
     _Pragma("GCC diagnostic push"); \
     PRAGMA(GCC diagnostic ignored #x)
#  define GCC_END_IGNORED_WARNING(x) \
     _Pragma("GCC diagnostic pop")
#else
   /** This is a noop for non-gcc compilers */
#  define GCC_BEGIN_IGNORED_WARNING(x)
   /** This is a noop for non-gcc compilers */
#  define GCC_END_IGNORED_WARNING(x)
#endif // __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6)

/*
 * Macros for calculating standard string lengths.
 *
 * FOO_MAX_WIDTH is at least as wide as the base10 string version of the largest
 * integer value of the relevant type.  A buffer of size FOO_MAX_WIDTH will be
 * large enough to sprintf a variable of the relevant type (including the
 * terminating NULL).
 */
/** Calculates the length of a stringified symbol value, including the
 *  terminating NULL. */
#define BASE10_WIDTH2(s) sizeof(#s)
/** Dereferences a symbol so its value can be stringified */
#define BASE10_WIDTH(s) BASE10_WIDTH2(s)
/** The size of a buffer large enough to hold a base 10 string version of the
 * largest unsigned 64-bit value */
#define UINT64_MAX_WIDTH BASE10_WIDTH(UINT64_MAX)
/** The size of a buffer large enough to hold a base 10 string version of the
 * largest unsigned 32-bit value */
#define UINT32_MAX_WIDTH BASE10_WIDTH(UINT32_MAX)

/**
 * \def JABBERWERX_ERROR(err, code)
 *
 * Macro to initialize an error context.
 *
 * \param err The pointer to the error context, or NULL if none
 * \param errcode The error code
 */
#define JABBERWERX_ERROR(err, errcode) \
    GCC_BEGIN_IGNORED_WARNING(-Waddress) \
        if ((err) != NULL) \
        { \
            (err)->code = (errcode); \
            (err)->message = jw_err_message((errcode)); \
            (err)->function = __func__; \
            (err)->file = __FILE__; \
            (err)->line = __LINE__; \
        } \
    GCC_END_IGNORED_WARNING(-Waddress)


/**
 * Enumeration of defined error codes.
 */
typedef enum
{
    /** No error */
    JW_ERR_NONE = 0,
    /** argument was invalid (beyond invariants) */
    JW_ERR_INVALID_ARG,
    /** context is not in a valid state */
    JW_ERR_INVALID_STATE,
    /** out of memory */
    JW_ERR_NO_MEMORY,
    /** buffer would overflow */
    JW_ERR_OVERFLOW,
    /** error connecting to a remote endpoint */
    JW_ERR_SOCKET_CONNECT,
    /** provided data could not be parsed by consuming entity */
    JW_ERR_BAD_FORMAT,
    /** invalid protocol */
    JW_ERR_PROTOCOL,
    /** timed out */
    JW_ERR_TIMEOUT,
    /** authentication-related error */
    JW_ERR_NOT_AUTHORIZED,
    /** functionality not implemented (often because of a compile-time switch */
    JW_ERR_NOT_IMPLEMENTED,
    /** user-defined error.  feel free to define specific user-defined errors as
     *  long as their values are greater than JW_ERR_USER */
    JW_ERR_USER,
} jw_errcode;

/**
 * An instance of an error context. Unlike other structures, it
 * is the API user's responsibility to allocate the structure; however
 * the values provided are considered constants, and MUST NOT be
 * deallocated.
 */
typedef struct
{
    /** The error code */
    jw_errcode   code;
    /** The human readable message for the error code */
    const char  *message;
    /** The function where the error occured, or "<unknown>"
        if it cannot be determined */
    const char  *function;
    /** The file where the error occured */
    const char  *file;
    /** The line number in the file where the error occured */
    unsigned long line;
} jw_err;


#ifdef __cplusplus
extern "C"
{
#endif

/**
 * Retrieves the error message for the given error code.
 *
 * \param code The error code to lookup
 * \retval const char * The message for {code}
 */
JABBERWERX_API const char * jw_err_message(jw_errcode code);

/**
 * Retrieves the (runtime) version string of this library.  This function can
 * be called without first calling jw_global_init().
 *
 * \param full true to return the full version (with build number), false to
 *             return the common version (without build number)
 * \retval const char * The version string.
 */
JABBERWERX_API const char * jw_version(bool full);

/**
 * Performs global initialization of the JabberWerxC library and sets the 3rd
 * party libraries to use JWC memory allocator functions.  It is currently not
 * required to call this function or its cleanup counterpart, but eventually
 * the proper functioning of JWC will depend on them.  This function may be
 * called multiple times, but will only have an effect the first time it is
 * called or the first time it is called after jw_global_cleanup() is called.
 *
 * This function can generate the following errors (set when returning false):
 * \li \c JW_ERR_NO_MEMORY if library stat could not be allocated.
 *
 * \param[out] err The error information (provide NULL to ignore).
 * \retval bool true if the library was initialized successfully.
 */
JABBERWERX_API bool jw_global_init(jw_err *err);

/**
 * Performs global cleanup of the JabberWerxC library and all used 3rd party
 * libraries.  This function can be called regardless of whether
 * jw_global_init() was ever called.  If this function is not called, valgrind
 * may report memory leaks.
 */
JABBERWERX_API void jw_global_cleanup();

#ifdef __cplusplus
}
#endif

#endif /* JABBERWERX_BASICS_H */
