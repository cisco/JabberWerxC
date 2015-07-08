/**
 * \file
 * \brief
 * Functions and data structures for JIDs.
 *
 * \b NOTE: This API is not thread-safe.  Users MUST ensure all jid instances
 * related to a particular jw_jid_ctx are never accessed simultaneously by
 * multiple threads.  Simultaneous access to jids in separate jw_jid_ctx
 * contexts is ok.
 *
 * \b NOTE: All strings passed to JID functions must be null-terminated UTF8
 * strings, and all strings returned from them are null-terminated UTF8 strings.
 * Be aware strlen() will return the number of bytes a string contains, not
 * necessarily the number of characters.
 *
 * \b NOTE: All localparts passed to JID functions (apart from
 * jw_jid_escape_localpart) must be escaped.  All returned localparts (except
 * those from jw_jid_unescape_localpart) are escaped.
 *
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

#ifndef JABBERWERX_JID_H
#define JABBERWERX_JID_H

#include "util/mem.h"


/** An instance of a JID context. */
typedef struct _jw_jid_ctx_int jw_jid_ctx;

/** An instance of a JID */
typedef struct _jw_jid_int jw_jid;


#ifdef __cplusplus
extern "C"
{
#endif

/**
 * Create a new jw_jid_ctx. The context will keep a reference to the JIDs
 * created with it.  JID lifetimes are managed by the context and any cached
 * jw_jids are completely destroyed when the context is destroyed.
 *
 * The context has a jw_pool associated with it for use by the user as an
 * onDestroy mechanism.  Users may access the pool using jw_jid_context_get_pool
 * and add a cleaner to be notified when the JIDs are about to be destroyed.
 *
 * This function can generate the following errors (set when returning false):
 * \li \c JW_ERR_NO_MEMORY if JID tables could not be initialized
 *
 * \invariant ctx != NULL
 * \param[in] bucket_count The number of buckets to use in the JID hashtable.
 *                        If 0, defaults to a size appropriate for clients.
 * \param[out] ctx The newly created JID context.
 * \param[out] err The error information (provide NULL to ignore)
 * \retval bool true if context was successfully created, otherwise false.
 */
JABBERWERX_API bool jw_jid_context_create(size_t       bucket_count,
                                          jw_jid_ctx **ctx,
                                          jw_err      *err);

/**
 * Destroy the given jw_jid_ctx. All jw_jids associated with this
 * context are completely destroyed regardless of their reference count.
 *
 * \invariant ctx != NULL
 * \param[in] ctx The jw_jid_ctx to destroy.
 */
JABBERWERX_API void jw_jid_context_destroy(jw_jid_ctx *ctx);

/**
 * Calls jw_jid_context_destroy on data associated with a jw_htable node.
 * This can be used to clean up a jid context when the keys are static
 * values.
 *
 * \param[in] replace Ignored
 * \param[in] destroy_key Ignored
 * \param[in] key Ignored
 * \param[in] data The jid context that will be destroyed.
 */
JABBERWERX_API void jw_jid_context_htable_cleaner(bool  replace,
                                                  bool  destroy_key,
                                                  void *key,
                                                  void *data);

/**
 * Get the jw_pool memory pool for the given context.
 * NOTE - Pool lifetime is controlled by the owning context, users
 *        must not free this pool reference.
 *
 * \invariant ctx != NULL
 * \param[in] ctx The jw_jid context
 * \retval jw_pool the associated memory pool.
 */
JABBERWERX_API jw_pool *jw_jid_context_get_pool(jw_jid_ctx *ctx);

/**
 * Create a new JID from a string representation of a complete JID.
 * The returned jw_jid may be explicitly freed via jw_jid_destroy, or may be
 * left to be automatically freed when the associated jw_jid_ctx is destroyed.
 *
 * It is important to note that each part of the given jidstr must conform to
 * the requirements detailed in the jw_jid_create_by_parts().
 *
 * This function can generate the following errors (set when returning false):
 * \li \c JW_ERR_INVALID_ARG if jidstr is NULL or cannot be parsed into a valid
 *          JID (see RFC 6122 Addressing)
 * \li \c JW_ERR_NO_MEMORY if JID structures could not be created.
 *
 * \invariant ctx != NULL
 * \invariant jid != NULL
 * \param[in] ctx The context to use.
 * \param[in] jidstr The JID string to be parsed into a jw_jid.
 * \param[out] jid The resultant jw_jid, set on success
 * \param[out] err The error information (provide NULL to ignore)
 * \retval bool true if successful, false otherwise.
 */
JABBERWERX_API bool jw_jid_create(jw_jid_ctx  *ctx,
                                  const char  *jidstr,
                                  jw_jid     **jid,
                                  jw_err      *err);

/**
 * Create a new JID from individual parts.
 * The returned jw_jid may be explicitly freed via jw_jid_destroy, or may be
 * left to be automatically freed when the associated jw_jid_ctx is destroyed.
 *
 * This function can generate the following errors (set when returning false):
 * \li \c JW_ERR_INVALID_ARG if parts cannot be parsed and combined into a valid
 *          JID (see RFC 3920 Addressing)
 * \li \c JW_ERR_NO_MEMORY if JID structures could not be initialized
 *
 * \invariant ctx != NULL
 * \invariant jid != NULL
 * \param[in] ctx The jw_jid_ctx to use.
 * \param[in] localpart The escaped localpart part of the JID.  May be
 *                      zero-length, or, equivalently, NULL.
 * \param[in] domainpart The domain part of the JID.  Must be a valid
 *                       DNS-resolvable hostname, a dotted IPv4 address, or a
 *                       square bracket-enclosed colon-separated IPv6 address.
 *                       Hostnames must conform to RFC 1123, e.g. only contain
 *                       valid characters and be less than 255 characters long.
 *                       The RFC is relaxed in that we allow underscores in the
 *                       hostname string.  A NULL or empty value results in an
 *                       invalid arg error response.
 * \param[in] resourcepart The resource part of the JID.  May be zero-length,
 *                         or, equivalently, NULL.
 * \param[out] jid The resultant jw_jid, set on success
 * \param[out] err The error information (provide NULL to ignore)
 * \retval bool true if successful, false otherwise.
 */
JABBERWERX_API bool jw_jid_create_by_parts(jw_jid_ctx *ctx,
                                           const char *localpart,
                                           const char *domainpart,
                                           const char *resourcepart,
                                           jw_jid     **jid,
                                           jw_err     *err);

/**
 * Increment a jid reference count.
 *
 * \invariant jid != NULL
 * \param[in] jid The JID to copy.
 * \retval jw_jid The newly copied jw_jid
*/
JABBERWERX_API jw_jid *jw_jid_copy(jw_jid *jid);

/**
 * Decrement the reference count for a jid and release memory as needed.
 *
 * \invariant jid != NULL
 * \param[in] jid The JID to release.
 */
JABBERWERX_API void jw_jid_destroy(jw_jid *jid);

/**
 * Get the given JID's context.
 *
 * \invariant jid != NULL
 * \retval jw_jid_ctx The associated context.
 */
JABBERWERX_API jw_jid_ctx *jw_jid_get_context(jw_jid *jid);

/**
 * Import a given JID into the given context and return a reference to the new
 * copy.  This function behaves like jw_jid_create with parsing and stringprep
 * optimizations.
 *
 * This function can generate the following errors (set when returning false):
 * \li \c JW_ERR_NO_MEMORY if copy could not be created.
 *
 * \invariant ctx != NULL
 * \invariant jid != NULL
 * \invariant cpy != NULL
 * \param[in] ctx The context into which this JID will be imported.
 * \param[in] jid The JID to import.
 * \param[out] cpy A copy of JID within the new context.
 * \param[out] err The error information (provide NULL to ignore)
 * \retval bool true if JID was successfully imported into ctx, else false.
 */
JABBERWERX_API bool jw_jid_import(jw_jid_ctx *ctx,
                                  jw_jid     *jid,
                                  jw_jid    **cpy,
                                  jw_err     *err);

/**
 * Parse jidstr to determine if it represents a valid JID (see
 * RFC3920#Addressing).  This returns false exactly when jw_jid_create returns
 * false, except that it cannot fail due to low memory conditions.
 *
 * \param[in] jidstr The JID string to parse and test.
 * \retval bool Returns true when jidstr is valid and false otherwise.
 */
JABBERWERX_API bool jw_jid_valid(const char *jidstr);

/**
 * Get the localpart part of JID as a string.
 *
 * \invariant jid != NULL
 * \param[in] jid The JID from which to get the localpart
 * \retval a String representing localpart. May be NULL if no localpart exists.
 *          localpart will be in escaped form.
 */
JABBERWERX_API const char *jw_jid_get_localpart(jw_jid *jid);

/**
 * Return the domain part of the JID as a string.
 *
 * \invariant jid != NULL
 * \param[in] jid The JID from which the domain is extracted.
 * \retval char* Returns the domain portion of the JID.
 */
JABBERWERX_API const char *jw_jid_get_domain(jw_jid *jid);

/**
 * Return the resource part of the JID as a string.
 *
 * \invariant jid != NULL
 * \param [in] jid The JID from which the resource is extracted.
 * \retval char* Returns the resource portion of the JID. May be NULL if
 *               resource does not exist.
 */
JABBERWERX_API const char *jw_jid_get_resource(jw_jid *jid);

/**
 * Return the bare JID ([localpart@]domain) as a string.
 *
 * \invariant jid != NULL
 * \param[in] jid The JID from which the bare JID is extracted.
 * \retval char* Returns the [localpart@]domain form of the JID.  If localpart
 * exists, it will be in escaped form.
 */
JABBERWERX_API const char *jw_jid_get_bare(jw_jid *jid);

/**
 * Return the full JID ([localpart@]domain[/resource]) as a string.
 *
 * \invariant jid != NULL
 * \param[in] jid The JID from which the full JID is extracted.
 * \retval char* Returns the [localpart@]domain[/resource] form of the JID.  If
 * localpart exists, it will be in escaped form.
 */
JABBERWERX_API const char *jw_jid_get_full(jw_jid *jid);

/**
 * Return the bare JID ([localpart@]domain) as a jw_jid.  The caller is
 * responsible for releasing the resultant JID using jw_jid_destroy.
 *
 * \invariant jid != NULL
 * \param[in] jid The JID from which the bare JID is extracted.
 * \retval jw_jid Returns a jw_jid populated with the [localpart@]domain form of
 *              the JID.  If JID was already a bare JID, the same JID is
 *              returned and its reference count will be increased. Caller must
 *              call jw_jid_destroy to free this reference, or else allow it to
 *              be reclaimed when the context is destroyed.
 */
JABBERWERX_API jw_jid *jw_jid_get_bare_jid(jw_jid *jid);

/**
 * Compare two JIDs.
 *
 * NULL < !NULL. Compares domain -> localpart -> resource.
 * For example;
 * \verbatim
 *  foo@bar1/res > foo1@bar0/res > foo0@bar0/res1 > foo0@bar0@res0
 *  foo@bar1/res > zzz@bar0/res
 *  foo1@bar/res > foo0@bar/res
 *  bar1/res1 > bar1/res0 > foo@bar0/res0
 *  foo@bar1 > bar0
 * \endverbatim
 *
 * \param[in] lhs "left hand side" JID. May be NULL.
 * \param[in] rhs "right hand side" JID. May be NULL.
 * \retval int When the comparison yields equality 0 is returned. See
 *             strcmp for the non-zero return value semantics.
 */
JABBERWERX_API int jw_jid_cmp(jw_jid *lhs, jw_jid *rhs);

/**
 * Escape a JID localpart character string according to XEP-0106.
 *
 * \b NOTE: This function will allocate the memory needed to store the escaped
 * localpart. The result MUST be released using jw_data_free.
 *
 * This function can generate the following errors (set when returning false):
 * \li \c JW_ERR_NO_MEM If space could not be allocated for result.
 *
 * \invariant result != NULL
 * \param[in]  localpart The null terminated localpart to be escaped. May be
 *             NULL.
 * \param[out] result The escaped version of localpart, NULL if localpart is
 *             NULL
 * \param[out] result_len The size of the result string, ignored if NULL.
 * \param[out] err The error information (provide NULL to ignore)
 * \retval bool true if encoding was successful, false otherwise.
*/
JABBERWERX_API bool jw_jid_escape_localpart(const char *localpart,
                                            char      **result,
                                            size_t     *result_len,
                                            jw_err     *err);

/**
 * Unescape a JID localpart character string according to XEP-0106
 *
 * \b NOTE: This function will allocate the memory needed to store the unescaped
 * localpart. The result MUST be released using jw_data_free.
 *
 * This function can generate the following errors (set when returning false):
 * \li \c JW_ERR_NO_MEM If space could not be allocated for result.
 *
 * \invariant result != NULL
 * \param[in]  localpart The null terminated localpart to be unescaped. May be
 *             NULL.
 * \param[out] result The unescaped version of localpart, NULL if localpart is
 *             NULL
 * \param[out] result_len The size of the result string, ignored if NULL.
 * \param[out] err The error information (provide NULL to ignore)
 * \retval bool true if encoding was successful, false otherwise.
 */
JABBERWERX_API bool jw_jid_unescape_localpart(const char *localpart,
                                              char      **result,
                                              size_t     *result_len,
                                              jw_err     *err);

#ifdef __cplusplus
}
#endif

#endif /* JABBERWERX_JID_H */
