/**
 * \file
 * \brief
 * Internal logging functions, not for use outside library and unit tests.
 *
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

#ifndef JABBERWERX_LOG_INT_H
#define JABBERWERX_LOG_INT_H

#include <jabberwerx/util/mem.h>


#ifdef __cplusplus
extern "C"
{
#endif

/**
 * Set the allocator and deallocator used for log messages.
 *
 * If used, this function should be called before any other log functions are
 * called.
 *
 * \param allocator the allocator to use (pass NULL to use the default:
 *   jw_data_malloc)
 * \param deallocator the deallocator to use (pass NULL to use the default:
 *   jw_data_free)
 */
void _jw_log_set_memory_funcs(jw_data_malloc_func allocator,
                              jw_data_free_func   deallocator);

#ifdef __cplusplus
}
#endif

#endif /* JABBERWERX_LOG_INT_H */
