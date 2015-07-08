/**
 * \file
 * \brief
 * Memory pool typedefs. private, not for use outside library and unit tests.
 * \see pools.h
 *
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

#ifndef JW_INCLUDE_POOL_TYPES_H
#define JW_INCLUDE_POOL_TYPES_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdlib.h>

/**
 * When DISABLE_POOL_PAGES is defined, page functionality is disabled by forcing
 * the page size to 0. All memory operations use jw_data_* functions directly.
 * jw_pool was designed to work correctly in this senario, see paragraph 2
 * of pool_page documentation below.
 *
 * Disabling page sub-allocations allows valgrind to fully inspect all pointer
 * allocations and usage, and gives a meaningful call stack when tracing
 * malloc origins (see valgrind documentation --track-origins).
 *
 * Page specific unit tests (in mem_test.c) are not included when
 * DISABLE_POOL_PAGES is defined.
 */
//#define DISABLE_POOL_PAGES

/**
 * Enable/disable memory pool paging by setting the pool's page size to 0.
 *
 * NOTE: Page size is only checked during construction, exisiting pools are not
 * effected by this function.
 *
 * \param[in] enable enable or disable pool paging for newly constructed jw_pools.
 */
void jw_pool_enable_paging(bool enable);

/**
 * Pools use "page"s, blocks of allocated mem, for allocation
 * and release efficiency. When possible pools "malloc" by just
 * return pointers into a page. When releasing pools free entire
 * pages, not pointer by pointer, very desirable behavior when
 * managing recursive data structures like DOMs.
 *
 * If a allocation request could not fit in any page, memory is
 * allocated directly. The resultant pointer is freed when the
 * pool is destroyed. If a request would fit in a page but the
 * current page doesn't have enough free spoace a new page is
 * allocated and used for the request.
 *
 * A page is a node in a LL. Not really necessary for
 * alloc/free logic but a list makes testing page much easier.
 * Without this list pages are still accessable through the
 * cleaner list (where the page is the arg passed to
 * a _pool_page_free cleaner) but it's confusing.
 */
typedef struct pool_page
{
    void*  block;
    size_t size;
    size_t used;
    struct pool_page *next;
} *_pool_page;

/**
 * pool_cleaners are callbacks fired when a pool is being destroyed.
 * A pool_cleaner_ctx is a node in a LL of cleaners. Each "context"
 * contains a cleaner ref and an argument to pass to the cleaner.
 * Typically the argument is the pointer that should be freed.
 * It is up to the cleaner to free arg if it is a pointer. pages
 * are freed using a page cleaner etc.
 */
typedef struct pool_cleaner_ctx
{
    jw_pool_cleaner cleaner;
    void*           arg;
    struct pool_cleaner_ctx *next;
} *_pool_cleaner_ctx;

/**
 * A pool is a head pointer to the page linked list, a head
 * pointer to the cleaners LL, the total number of bytes
 * allocated by this pool (pages*page size)+off page allocations
 * and the page size given to the pool at creation.
 */
typedef struct _jw_pool_int
{
    size_t size;
    size_t page_size;
    struct pool_cleaner_ctx *cleaners;
    struct pool_cleaner_ctx *tail;
    struct pool_page        *pages;
} _jw_pool;

#ifdef __cplusplus
}
#endif

#endif  /* JW_INCLUDE_POOL_TYPES_H */
