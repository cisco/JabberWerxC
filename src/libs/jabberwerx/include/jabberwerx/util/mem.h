/**
 * \file
 * \brief
 * This file contains JabberWerxC allocation related functions
 * and jw_pool objects.
 *
 * Memory Pools
 * A memory pool is a minimal memory manager
 * that simplifies freeing memory in non-trivial data
 * structures. Two examples in the JabberWerxC API
 * using memory pools are jw_dom and jw_jid.
 *
 * Pools are passed a "block" size on creation.
 * Each pool sub-allocates from its block, which grows as
 * needed. Blocks allow large amounts of memory to be freed
 * quickly.
 * If no block size is given, or a request is made
 * that is too large for a single, empty block to hold, memory is
 * allocated directly but still freed when the pool is destroyed.
 *
 * Applications can register callbacks, call cleaners, that will
 * be triggered when the pool is destroyed. These cleaners will
 * be executed in the same order they were registered. For example,
 * jw_jid uses a cleaner to automatically decrement reference counts
 * if the jw_jid is used within the same context as the jw_pool.
 *
 * Pools work well with data structures that are relatively
 * static, unchanging. Pools have no way to free a particular
 * pointer and no garbage collection. Thus changes to a pool
 * managed data structure may result in unreferenced but still
 * allocated memory. These are cleaned up when the pool is
 * destroyed.
 *
 * Because pools free everything on their destruction they also
 * work well for tasks were the lifetime of the pool is short.
 *
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

#ifndef JABBERWERX_UTIL_MEM_H
#define JABBERWERX_UTIL_MEM_H

#include "../basics.h"


/** An instance of a memory pool */
typedef struct _jw_pool_int jw_pool;


/**
 * A callback invoked when the bound pool entry is destroyed.
 *
 * \param[in] arg Argument bound to cleaner when it was added.
 *                  Typically the pointer about to be freed
 *                  but it may be any user data.
 */
typedef void (*jw_pool_cleaner)(void *arg);

/**
 * Callback signature used by jw_data_malloc.
 *
 * \param[in] size Size of the memory to be allocated.
 * \retval void* Pointer to memory block created by jw_data_malloc
 */
typedef void * (*jw_data_malloc_func)(size_t size);

/**
 * Callback signature used by jw_data_realloc.
 *
 * \param[in] ptr Pointer to the memory block that will be altered.
 * \param[in] size Size of the final memory block.
 * \retval void* Pointer to memory block created by jw_data_realloc
 */
typedef void * (*jw_data_realloc_func)(void *ptr, size_t size);

/**
 * Callback signature used by jw_data_free.
 *
 * \param[in] ptr Pointer to memory block that will be freed.
 */
typedef void (*jw_data_free_func)(void *ptr);


#ifdef __cplusplus
extern "C"
{
#endif

/**
 * Replace memory allocators used by this library.
 *
 * If you call this function, it is imperative that you call it before any
 * other function in either the jabberwerx library or any dependent library
 * affected by the jw_global_init() function.  This is to ensure that all memory
 * allocated with a particular malloc implementation is freed via the
 * appropriately paired free implementation.
 *
 * Any memory function can be set to its default state by passing in NULL. If
 * one function is going to be set to its default state, it is preferred to set
 * all of them to their default states.
 *
 * \param[in] malloc_func Function to replace malloc
 * \param[in] realloc_func Function to replace realloc
 * \param[in] free_func Function to replace free
 */
JABBERWERX_API void jw_data_set_memory_funcs(jw_data_malloc_func  malloc_func,
                                             jw_data_realloc_func realloc_func,
                                             jw_data_free_func    free_func);

/**
 * Release memory allocated by the JabberWerxC library.
 *
 * jw_data_free must be used to release any memory allocated by jabberwerx, and
 * cannot be used to free memory allocated elsewhere.
 *
 * The library typically allocates memory in functions returning unstructured
 * data. The function documentation will explicitly state what should be
 * released using jw_data_free.
 *
 * \see api-design for a detailed discussion of jwc memor  philosophy and design
 *
 * \param[in] ptr The pointer to be freed. May be NULL.
 */
JABBERWERX_API void jw_data_free(void *ptr);

/**
 * Allocate 'size' bytes of memory and return a pointer of the allocated memory.
 *
 * \see api-design for a detailed discussion of jwc memory philosophy and design
 *
 * \param[in] size The number of bytes to allocate.
 * \retval void* Pointer to the allocated memory
 */
JABBERWERX_API void * jw_data_malloc(size_t size);

/**
 * Changes the size of the memory block pointed to by 'ptr' to size 'size'.
 *
 * \see api-design for a detailed discussion of jwc memory philosophy and design
 *
 * \param[in] ptr The original block of memory allocated through jw_data_malloc.
 *              if ptr is NULL, this function is equivalent to jw_data_malloc.
 * \param[in] size The number of bytes to reallocate.
 * \retval void* Pointer to the resized memory block.
 */
JABBERWERX_API void * jw_data_realloc(void *ptr, size_t size);

/**
 * Contiguously allocates enough space for nmemb objects that are size bytes of
 * memory each and returns a pointer to the allocated memory.  The allocated
 * memory is filled with bytes of value zero.
 *
 * \see api-design for a detailed discussion of jwc memory philosophy and design
 *
 * \param[in] nmemb The number of contiguous chunks to allocate.
 * \param[in] size The number of bytes to allocate per chunk.
 * \retval void* Pointer to the allocated memory
 */
JABBERWERX_API void * jw_data_calloc(size_t nmemb, size_t size);

/**
 * Duplicate a string by allocating memory
 *
 * \see api-design for a detailed discussion of jwc memory philosophy and design
 *
 * This function can generate the same errors as jw_data_malloc()
 *
 * \param[in] src The null (\\0) terminated string to copy. May be NULL
 * \retval char * Returns the copy of the string, allocated with
 *                jw_data_malloc(), NULL if src is NULL
 */
JABBERWERX_API char * jw_data_strdup(const char *src);

/**
 * Duplicate a string by allocating memory
 *
 * \see api-design for a detailed discussion of jwc memory philosophy and design
 *
 * This function can generate the same errors as jw_data_malloc()
 *
 * \param[in] src The potentially null (\\0) terminated string to copy. May be
 *                  NULL
 * \param[in] len The maximum number of bytes in src to copy.
 * \retval char * Returns the copy of the string containing the lesser
 *                of the full string (null terminated) or len bytes
 *                (result additionally null terminated).
 *                Allocated with jw_data_malloc(), NULL if src is NULL
 */
JABBERWERX_API char * jw_data_strndup(const char *src,
                                      size_t      len);

/**
 * Create a new memory pool using the given block size.
 *
 * This function can generate the following errors, set when returning false:
 * \li \c JW_ERR_NO_MEMORY if the pool could not be allocated
 *
 * \invariant pool != NULL
 * \param[in] size block byte size, 0 implies always use jw_data_malloc.
 * \param[out] pool Newly constructed memory pool
 * \param[out] err The error information (provide NULL to ignore)
 * \retval bool Returns true if pool was successfully created,
 *              false otherwise.
 */
JABBERWERX_API bool jw_pool_create(size_t    size,
                                   jw_pool **pool,
                                   jw_err   *err);
/**
 * Free any memory allocated by the given pool, including the pool itself.
 *
 * Bound jw_pool_cleaner callbacks are invoked before any memory is freed.
 *
 * \invariant pool != NULL
 * \param pool The memory pool to free
 */
JABBERWERX_API void jw_pool_destroy(jw_pool *pool);

/**
 * Associate a callback to be fired when the given pointer is freed during the
 * given pool's destruction.
 *
 * This function can generate the following errors, set when returning false:
 * \li \c JW_ERR_NO_MEMORY if space for cleaner could not be allocated
 *
 * \invariant pool != NULL
 * \invariant callback != NULL
 * \param[in] pool The memory pool in which the given pointer was allocated
 * \param[in] callback The jw_pool_cleaner callback to be fired
 * \param[in] arg An argument past to callback, typically the pointer
 * \param[out] err The error information (provide NULL to ignore)
 * \retval bool Returns true if cleaner was successfully added, false otherwise.
 */
JABBERWERX_API bool jw_pool_add_cleaner(jw_pool        *pool,
                                        jw_pool_cleaner callback,
                                        void           *arg,
                                        jw_err         *err);

/**
 * Allocate memory from the given pool.
 *
 * This function can generate the following errors, set when returning false:
 * \li \c JW_ERR_NO_MEMORY if the ptr could not be allocated
 *
 * \invariant pool != NULL
 * \invariant ptr != NULL
 * \param[in] pool The jw_pool from which to allocate memory
 * \param[in] size The number of bytes to allocate.
 * \param[out] ptr The newly allocated pointer. NULL if size == 0
 * \param[out] err The error information (provide NULL to ignore)
 * \retval bool Returns true if pool was successfully created, false otherwise.
 */
JABBERWERX_API bool jw_pool_malloc(jw_pool *pool,
                                   size_t   size,
                                   void   **ptr,
                                   jw_err  *err);

/**
 * Calculate memory needed and allocate in given pool.
 *
 * This function can generate the following errors set when returning false:
 * \li \c JW_ERR_NO_MEMORY if the ptr could not be allocated
 *
 * \invariant pool != NULL
 * \invariant ptr != NULL
 * \param[in] pool The jw_pool from which to allocate memory
 * \param[in] num Number of items
 * \param[in] size Size of one item
 * \param[out] ptr Pointer to newly allocated block of size num*size. NULL if
 *                   num*size == 0
 * \param[out] err The error information (provide NULL to ignore)
 * \retval bool Returns true if ptr was successfully allocated, false otherwise.
 */
JABBERWERX_API bool jw_pool_calloc(jw_pool *pool,
                                   size_t   num,
                                   size_t   size,
                                   void   **ptr,
                                   jw_err  *err);

/**
 * Duplicate a string by allocating memory in the given pool.
 *
 * This function can generate the following errors set when returning false:
 * \li \c JW_ERR_NO_MEMORY if the cpy could not be allocated
 *
 * \invariant pool != NULL
 * \invariant cpy != NULL
 * \param[in] pool The jw_pool from which to allocate memory
 * \param[in] src The string to copy. May be NULL
 * \param[out] cpy The copy of src allocated in pool. NULL if src was NULL.
 * \param[out] err The error information (provide NULL to ignore)
 * \retval bool Returns true if cpy was successfully created, false otherwise.
 */
JABBERWERX_API bool jw_pool_strdup(jw_pool    *pool,
                                   const char *src,
                                   char      **cpy,
                                   jw_err     *err);

#ifdef __cplusplus
}
#endif

#endif  /* JABBERWERX_UTIL_MEM_H */
