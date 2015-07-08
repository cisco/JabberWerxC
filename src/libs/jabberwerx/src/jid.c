/**
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

#include <assert.h>
#include <inttypes.h>
#include <string.h>

#include "jabberwerx/util/str.h"
#include "jabberwerx/util/htable.h"
#include "jabberwerx/util/log.h"
#include "jabberwerx/jid.h"
#include "include/unicode_int.h"


// constants
#define MAX_LEN_INCOMING_STRING  4096
#define MAX_LEN_COMPONENT        1023
#define MAX_LEN_DNS_LABEL        63
#define MAX_LEN_DNS_FQHN         255
#define DEFAULT_JID_BUCKET_COUNT 103

/**
 * An enumeration of parts of JID and valid combinations of those parts.
 * This enumeration assigns integer values so they may be used as bit flags.
 */
typedef enum
{
    /** node part of JID */
    JW_JID_LOCALPART    = 1 << 1,
    /** domain part of JID or just a domain JID */
    JW_JID_DOMAIN       = 1 << 2,
    /** resource part of JID */
    JW_JID_RESOURCE     = 1 << 3,
    /** node@domain JID */
    JW_JID_BARE         = JW_JID_LOCALPART | JW_JID_DOMAIN,
    /** domain/resource JID */
    JW_JID_DOMAIN_FULL  = JW_JID_DOMAIN | JW_JID_RESOURCE,
    /** node@domain/resource JID */
    JW_JID_FULL         = JW_JID_BARE | JW_JID_RESOURCE
} jw_jid_part;

/**
 * JID context
 */
typedef struct _jw_jid_ctx_int
{
    /** for client use as an onDestroy mechanism -- not used internally */
    jw_pool *pool;

    /** maps jidstr -> jw_jid **/
    jw_htable *jids;
} _jw_jid_ctx;

/**
 * JID struct declaration.  After initialization, all struct members except for
 * refcount are read-only.
 */
typedef struct _jw_jid_int
{
    /** remember the context so we can find existing or allocate new
     *  subcomponent jids when subcomponents are requested */
    jw_jid_ctx *ctx;

    /** refcount so we know when to free memory */
    size_t refcount;

    /** a bitmask detailing which jid components exist in str */
    jw_jid_part componentsMask;

    /** if this jid has a resource, keep a reference to the bare jid, which has
     *  its refcount increased */
    struct _jw_jid_int * bareJid;

    /** if this is a bare jid and has a localpart, keep a copy of it here so it
     *  can be accessed and returned as a null terminated string.  if this is
     *  not a bare jid, this points to memory that is allocated as part of the
     *  bare jid, which is guaranteed to exist, due to refcounting, for at least
     *  as long as this jid. */
    uint8_t * localpart;

    /** pointer to the null terminated domain string.  this will point to some
     *  offset within a str member, and never needs to be individually freed. */
    uint8_t * domain;

    /** if this jid is not a bare jid, this will point to the null terminated
     *  resource string.  this will point to some offset within the str member,
     *  and never needs to be individually freed. */
    uint8_t * resource;

    /** extra memory allocated beyond the end of the struct to accommodate the
     *  null-terminated full or bare jid string */
    uint8_t str[];
} _jw_jid;


/**
 * Returns whether the given jid is a bare jid.  Bare jids own the allocated
 * memory for localpart.
 */
static bool _is_bare_jid(jw_jid *jid)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(NULL != jid);

    return 0 == (jid->componentsMask & JW_JID_RESOURCE);
}

/**
 * Frees memory allocated for the jid.  This assumes that the refcount for this
 * instance is zero, but the associated bare JID may not be haver refcount zero.
 */
static void _free_jid(bool replace,
                      bool destroy_key,
                      void *key,
                      void *data)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    UNUSED_PARAM(replace);
    UNUSED_PARAM(destroy_key);
    UNUSED_PARAM(key);

    assert(!replace);
    assert(data);

    jw_jid *jid = (jw_jid*)data;

    // if this is a bare jid, free localpart
    if (_is_bare_jid(jid))
    {
        // it's ok if localpart is NULL
        jw_data_free(jid->localpart);
    }

    // this includes the chunk used for the str member
    jw_data_free(jid);
}

/**
 * Returns true if the given string looks like an ipv6 address.  We return
 * true if the string is surrounded in square brackets and contains nothing
 * but hex digits and colons between them.  Since the address is already
 * normalized, we assume all letter digits are lower case.
 */
static bool _match_ipv6_address(const uint8_t * normalizedIpv6Addr, size_t len)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    // shortest possible ipv6 address is "[::1]"
    if (5 > len)
    {
        return false;
    }

    size_t bracketIdx = len - 1;
    if ('[' == normalizedIpv6Addr[0] && ']' == normalizedIpv6Addr[bracketIdx])
    {
        for (size_t idx = 1; idx < bracketIdx; ++idx)
        {
            uint8_t curChar = normalizedIpv6Addr[idx];
            if (':' == curChar ||
                ('0' <= curChar && '9' >= curChar) ||
                ('a' <= curChar && 'f' >= curChar))
            {
                // good so far
                continue;
            }

            // TODO: log reason for error
            return false;
        }
        return true;
    }

    return false;
}

/**
 * Returns true if normalizedLocalpart is NULL or conforms to requirements.
 */
static bool _validate_localpart(const uint8_t * normalizedLocalpart,
                                size_t          normalizedLocalpartLen,
                                jw_err        * err)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    if (NULL == normalizedLocalpart)
    {
        return true;
    }

    // _normalize ensures that all lengths are at least 1, so the -1 is safe
    const uint8_t * lastCharPtr =
            &normalizedLocalpart[normalizedLocalpartLen-1];

    // verify that there are no preceding or trailing escaped whitespace chars
    // in localpart
    if (('\\' == *normalizedLocalpart &&
         '2'  == *(normalizedLocalpart+1) &&
         '0'  == *(normalizedLocalpart+2)) ||
        ((normalizedLocalpartLen > 3) &&
         '0'  == *lastCharPtr &&
         '2'  == *(lastCharPtr-1) &&
         '\\' == *(lastCharPtr-2)))
    {
        // TODO: log reason for error
        JABBERWERX_ERROR(err, JW_ERR_INVALID_ARG);
        return false;
    }

    return true;
}

/**
 * Returns true if normalizedDomain appears to be one of the following:
 * - ipv4 address (we don't check numerical ranges, though)
 * - ipv6 address (see previous function)
 * - internationalizable domain name (we ensure that it can be punycoded)
 */
static bool _validate_domain(const uint8_t * normalizedDomain,
                             size_t          normalizedDomainLen,
                             jw_err        * err)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(NULL != normalizedDomain);
    assert(0 < normalizedDomainLen);

    // check for IPv6 addresses first.  it is too complicated to interweave
    // this logic into the next for loop.  It will likely fail after the first
    // character anyway, so there shouldn't be a noticeable performance drop.
    if (_match_ipv6_address(normalizedDomain, normalizedDomainLen))
    {
        return true;
    }

    size_t totalHostLen     = 0;
    size_t curLabelStartIdx = 0;
    bool   curLabelIsAscii  = true;

    // this function basically follows RFC 3490 4.1 ToAscii, but starts at
    // step 3 as we should already have been given a host that has been
    // nameprepped and it will not return a punycoded result, but instead
    // just verifies that the domain would be valid if punycoded
    for (size_t idx = 0; normalizedDomainLen > idx; ++idx)
    {
        uint8_t curChar = normalizedDomain[idx];
        bool isLastChar = normalizedDomainLen-1 == idx;

        if (0x7f < curChar)
        {
            curLabelIsAscii = false;
        }
        else
        {
            // step 3a: validate the absence of these code points.
            // this differs from a strict appliance of step 3a in that we
            // allow the underscore character so as to not exclude
            // standards-ignoring windows machines
            if ((0x2C >= curChar) ||
                (0x2F == curChar) ||
                ((0x3A <= curChar) && (0x40 >= curChar)) ||
                ((0x5B <= curChar) && (0x5E >= curChar)) ||
                (0x60 == curChar) ||
                ((0x7B <= curChar) && (0x7f >= curChar)))
            {
                // TODO: log reason for error
                JABBERWERX_ERROR(err, JW_ERR_INVALID_ARG);
                return false;
            }
        }

        if ('.' == curChar || isLastChar)
        {
            if ('.' == curChar && isLastChar)
            {
                // the next label would be empty
                // TODO: log reason for error
                JABBERWERX_ERROR(err, JW_ERR_INVALID_ARG);
                return false;
            }

            size_t labelLastCharIdx = isLastChar ? idx : idx-1;

            // ensure label isn't empty
            if (curLabelStartIdx >= labelLastCharIdx)
            {
                // TODO: log reason for error
                JABBERWERX_ERROR(err, JW_ERR_INVALID_ARG);
                return false;
            }

            // if this is the first and only label, check for the special case
            // where the entire hostname is "-internal"
            if (0 == curLabelStartIdx && isLastChar)
            {
                if (0 == jw_strcmp("-internal", (const char *)normalizedDomain))
                {
                    return true;
                }
            }

            // step 3b: '-' can't appear as the first or last char of any label
            if ('-' == normalizedDomain[curLabelStartIdx] ||
                '-' == normalizedDomain[labelLastCharIdx])
            {
                // TODO: log reason for error
                JABBERWERX_ERROR(err, JW_ERR_INVALID_ARG);
                return false;
            }

            const uint8_t * label = &normalizedDomain[curLabelStartIdx];
            int labelLen = labelLastCharIdx - curLabelStartIdx + 1;
            if (!curLabelIsAscii)
            {
                // steps 4-7: if there are non-ascii characters, fail if there
                // is already an ACE prefix, otherwise, punycode it
                if (0 == strncmp("xn--", (const char *)label, 4))
                {
                    // TODO: log reason for error
                    JABBERWERX_ERROR(err, JW_ERR_INVALID_ARG);
                    return false;
                }

                // doesn't actually allocate any memory, just gets the length
                // of the string that would be created
                labelLen = unicode_make_ace_label_int(label, labelLen, NULL, 0);
                if (0 >= labelLen)
                {
                    // TODO: log reason for error
                    JABBERWERX_ERROR(err, JW_ERR_INVALID_ARG);
                    return false;
                }
            }

            // step 8: ensure label length is under the limit
            if (MAX_LEN_DNS_LABEL < labelLen)
            {
                // TODO: log reason for error
                JABBERWERX_ERROR(err, JW_ERR_INVALID_ARG);
                return false;
            }

            totalHostLen += labelLen + (isLastChar ? 0 : 1);
            curLabelStartIdx = idx + 1;
            curLabelIsAscii = true;
        }
    }

    // ensure total hostname length is under the limit
    if (MAX_LEN_DNS_FQHN < totalHostLen)
    {
        // TODO: log reason for error
        JABBERWERX_ERROR(err, JW_ERR_INVALID_ARG);
        return false;
    }

    return true;
}

/**
 * Parses a jidstr into its component parts.  If a part does not exist, NULL
 * is returned in the corresponding pointer.  If jidstr is malformed, false
 * is returned and err is set.  Length restrictions are not enforced here.
 *
 * Well-formed input:
 *   domain
 *   localpart@domain
 *   domain/resource
 *   localpart@domain/resource
 */
static bool _parse_jid(const uint8_t  *jidstr,
                       size_t         *jidstrLen,
                       const uint8_t **localpart,
                       size_t         *localpartLen,
                       const uint8_t **domain,
                       size_t         *domainLen,
                       const uint8_t **resource,
                       size_t         *resourceLen,
                       jw_err         *err)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(NULL != jidstr);
    assert(NULL != jidstrLen);
    assert(NULL != localpart);
    assert(NULL != localpartLen);
    assert(NULL != domain);
    assert(NULL != domainLen);
    assert(NULL != resource);
    assert(NULL != resourceLen);

    int localpartDelimIdx = -1;
    int domainDelimIdx    = -1;

    const uint8_t * curChar = jidstr;
    while ('\0' != *curChar)
    {
        // if we already found the domain delimiter, just count characters
        if (-1 != domainDelimIdx)
        {
            ++curChar;
            continue;
        }

        // if we find a username delimiter, and we haven't found one already,
        // record it
        if (('@' == *curChar) && (-1 == localpartDelimIdx))
        {
            if (curChar == jidstr)
            {
                // TODO: log reason for failure
                // JID has a user delim but no user; bail
                JABBERWERX_ERROR(err, JW_ERR_INVALID_ARG);
                return false;
            }

            // record index for localpart delimiter
            localpartDelimIdx = curChar - jidstr;
        }
        else if ('/' == *curChar)
        {
            // search for domain delimiter
            if (curChar == jidstr || '\0' == *(curChar + 1))
            {
                // TODO: log reason for failure
                // jid has a resource but no user or domain, it has a
                // resource delimiter but no resource string
                JABBERWERX_ERROR(err, JW_ERR_INVALID_ARG);
                return false;
            }

            // record index for domain delimeter
            domainDelimIdx = curChar - jidstr;
        }

        ++curChar;
    }

    if (curChar == jidstr)
    {
        // TODO: log reason for failure
        // domain string not found
        JABBERWERX_ERROR(err, JW_ERR_INVALID_ARG);
        return false;
    }

    // set output variables
    *jidstrLen = curChar - jidstr;
    *domainLen = *jidstrLen;

    if (-1 == localpartDelimIdx)
    {
        *localpart = NULL;
        *domain = jidstr;
        *localpartLen = 0;
    }
    else
    {
        *localpart = jidstr;
        *domain = jidstr + localpartDelimIdx + 1;
        *localpartLen = localpartDelimIdx;
        *domainLen -= *localpartLen + 1;
    }

    if (-1 == domainDelimIdx)
    {
        *resource = NULL;
        *resourceLen = 0;
    }
    else
    {
        *resource = jidstr + domainDelimIdx + 1;
        *resourceLen = curChar - *resource;
        *domainLen -= *resourceLen + 1;
    }

    return true;
}

/**
 * Returns true if input is NULL or entirely consists of lowercase ascii text or
 * some simple punctuation characters that universally do not require
 * normalization.
 */
static bool _is_normalized_ascii(const uint8_t * jidComponent, size_t len)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    if (NULL == jidComponent)
    {
        return true;
    }

    for (size_t idx = 0; len > idx; ++idx)
    {
        uint8_t curChar = jidComponent[idx];

        // TODO: compile full list of pre-prepped ASCII characters
        if (0x2C >= curChar ||
            0x2F == curChar ||
            (0x3A <= curChar && 0x5E >= curChar) ||
            0x60 == curChar ||
            0x7b <= curChar)
        {
            return false;
        }
    }

    return true;
}

/**
 * Normalize given string and enforces post-normalize length restrictions.  That
 * is, only returns with success if the normalized string is between 1 and
 * normalizedJidComponentBufSize-1 bytes long.
 */
static bool _normalize(
            jw_jid_part componentType, const uint8_t * jidComponent,
            size_t jidComponentLen, uint8_t * normalizedJidComponentBuf,
            size_t normalizedJidComponentBufSize,
            size_t * normalizedJidComponentLen, jw_err * err)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    int normalizedStrLen;

    switch(componentType)
    {
    case JW_JID_LOCALPART:
        normalizedStrLen = unicode_nodeprep_int(jidComponent, jidComponentLen,
                                                normalizedJidComponentBuf,
                                                normalizedJidComponentBufSize);
        break;

    case JW_JID_DOMAIN:
        normalizedStrLen = unicode_nameprep_int(jidComponent, jidComponentLen,
                                                normalizedJidComponentBuf,
                                                normalizedJidComponentBufSize);
        break;

    case JW_JID_RESOURCE:
        normalizedStrLen = unicode_resourceprep_int(
                jidComponent, jidComponentLen,
                normalizedJidComponentBuf, normalizedJidComponentBufSize);
        break;

    default:
        assert(false);
        jw_log(JW_LOG_ERROR, "Unknown component type: %d", componentType);
        return false;
    }

    // output must be at least 1 character long
    if (2 > normalizedStrLen)
    {
        // TODO: log reason for error
        JABBERWERX_ERROR(err, JW_ERR_INVALID_ARG);
        return false;
    }

    *normalizedJidComponentLen = normalizedStrLen;
    return true;
}

/**
 * Create a jid out of a normalized jidstr or increment the refcount if the jid
 * already exists.  If allocatedJid is non-NULL, it is assumed to be the
 * container for normalizedJidstr and is used for the newly created jid.  It is
 * further assumed to be uninitialized except for its str member.  It is freed
 * with jw_data_free if the jid that would be created already exists in the
 * hashtable or if this function would return with error.
 *
 * If this jid is not a bare jid and is not already found in the cache, the
 * associated bare jid will be created.
 *
 * If normalizedJidstrLen is 0 then we calculate it internally.
 * normalizedJidstr is assumed to be null terminated regardless of the value
 * of normalizedJidstrLen.
 */
static bool _create_jid(jw_jid_ctx     *ctx,
                        jw_jid         *allocatedJid,
                        const uint8_t *normalizedJidstr,
                        size_t         normalizedJidstrLen,
                        jw_jid_part    componentTypeMask,
                        size_t         localpartLen,
                        size_t         domainLen,
                        size_t         resourceLen,
                        jw_jid        **jid,
                        jw_err        *err)
{
    JW_LOG_TRACE_FUNCTION("allocatedJid=%p; normalizedJidstr(%zd)='%.*s';"
            " localpartLen=%zd; domainLen=%zd; resourceLen=%zd;"
            " componentTypeMask=0x%x", (void *)allocatedJid,
            normalizedJidstrLen, (int)normalizedJidstrLen, normalizedJidstr,
            localpartLen, domainLen, resourceLen, componentTypeMask);

    assert(NULL != ctx);
    assert(NULL != normalizedJidstr);
    assert(0 != componentTypeMask);
    assert(0 < domainLen);
    assert(NULL != jid);
    if (componentTypeMask & JW_JID_LOCALPART) { assert(0 < localpartLen); }
    if (componentTypeMask & JW_JID_RESOURCE)  { assert(0 < resourceLen);  }

    // if normalizedJidstr is already null-terminated, check to see if it is
    // in the cache (we can't check otherwise since jw_htable_get doesn't take
    // a length parameter, and normalizedJidstr may not be null terminated
    // at normalizedJidstrLen)
    if (0 == normalizedJidstrLen ||
            '\0' == normalizedJidstr[normalizedJidstrLen])
    {
        jw_jid *cachedJid = jw_htable_get(ctx->jids, normalizedJidstr);
        if (NULL != cachedJid)
        {
            jw_log(JW_LOG_DEBUG, "found jid in cache");

            // if we allocated memory in preparation for jid creation, free it
            if (NULL != allocatedJid)
            {
                jw_data_free(allocatedJid);
            }

            ++cachedJid->refcount;
            *jid = cachedJid;
            return true;
        }
    }

    if (0 == normalizedJidstrLen)
    {
        normalizedJidstrLen = strlen((const char *)normalizedJidstr);
    }

    // if this is a full jid, create (or get a reference to) its bare jid
    jw_jid *bareJid = NULL;
    if (0 != resourceLen)
    {
        // bareJid is created with a reference count of 1.  since we hold the
        // only reference to it, there is no need to increment it again
        if (!_create_jid(ctx, NULL,
                normalizedJidstr, normalizedJidstrLen-(resourceLen+1),
                componentTypeMask^JW_JID_RESOURCE, localpartLen, domainLen, 0,
                &bareJid, err))
        {
            if (NULL != allocatedJid)
            {
                jw_data_free(allocatedJid);
            }
            return false;
        }
    }

    // construct a new jid if necessary
    if (NULL == allocatedJid)
    {
        allocatedJid = jw_data_malloc(sizeof(_jw_jid)+normalizedJidstrLen+1);
        if (NULL == allocatedJid)
        {
            if (NULL != bareJid)
            {
                jw_jid_destroy(bareJid);
            }

            jw_log(JW_LOG_WARN, "failed to allocate jid state");
            JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
            return false;
        }

        memcpy(allocatedJid->str, normalizedJidstr, normalizedJidstrLen);
        allocatedJid->str[normalizedJidstrLen] = '\0';
    }

    // if we haven't already checked, ensure we don't already have this in
    // the cache
    if ('\0' != normalizedJidstr[normalizedJidstrLen])
    {
        jw_jid *cachedJid = jw_htable_get(ctx->jids, allocatedJid->str);
        if (NULL != cachedJid)
        {
            jw_data_free(allocatedJid);

            if (NULL != bareJid)
            {
                jw_jid_destroy(bareJid);
            }

            ++cachedJid->refcount;
            *jid = cachedJid;

            return true;
        }
    }

    allocatedJid->ctx = ctx;
    allocatedJid->componentsMask = componentTypeMask;
    allocatedJid->refcount = 1;
    allocatedJid->bareJid = bareJid;

    // fill in pointers
    if (0 == resourceLen)
    {
        // initialize bare jid
        allocatedJid->resource = NULL;

        if (0 == localpartLen)
        {
            allocatedJid->domain = allocatedJid->str;
            allocatedJid->localpart = NULL;
        }
        else
        {
            allocatedJid->domain = allocatedJid->str + localpartLen + 1;
            allocatedJid->localpart = jw_data_malloc(localpartLen + 1);
            if (NULL == allocatedJid->localpart)
            {
                jw_data_free(allocatedJid);

                if (NULL != bareJid)
                {
                    jw_jid_destroy(bareJid);
                }

                JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
                return false;
            }

            memcpy(allocatedJid->localpart, allocatedJid->str, localpartLen);
            allocatedJid->localpart[localpartLen] = '\0';
        }
    }
    else
    {
        // initialize full jid
        allocatedJid->localpart = bareJid->localpart;
        allocatedJid->domain = bareJid->domain;

        size_t resourceOffset = 0;
        resourceOffset += localpartLen ? localpartLen + 1 : 0;
        resourceOffset += domainLen + 1;

        allocatedJid->resource = &allocatedJid->str[resourceOffset];
    }

    // add jid to cache
    if (!jw_htable_put(ctx->jids,
                       allocatedJid->str,
                       allocatedJid,
                       _free_jid,
                       err))
    {
        if (_is_bare_jid(allocatedJid))
        {
            jw_data_free(allocatedJid->localpart);
        }
        jw_data_free(allocatedJid);

        if (NULL != bareJid)
        {
            jw_jid_destroy(bareJid);
        }

        return false;
    }

    *jid = allocatedJid;

    return true;
}

/**
 * Create a jid from pre-vetted and normalized parts.
 *
 * If length arguments are 0 and their associated strings are non-NULL, strings
 * are assumed to be null-terminated.
 */
static bool _create_jid_from_normalized_parts(
                        jw_jid_ctx     *ctx,
                        const uint8_t *normalizedLocalpart,
                        size_t         normalizedLocalpartLen,
                        const uint8_t *normalizedDomain,
                        size_t         normalizedDomainLen,
                        const uint8_t *normalizedResource,
                        size_t         normalizedResourceLen,
                        jw_jid        **jid,
                        jw_err        *err)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(NULL != ctx);
    assert(NULL != jid);
    assert(NULL != normalizedDomain);
    assert(0 < normalizedDomainLen);

    size_t jidstrLen = 0;
    jw_jid_part componentTypeMask = 0;
    if (NULL != normalizedLocalpart)
    {
        assert(0 < normalizedLocalpartLen);

        jidstrLen += normalizedLocalpartLen + 1;
        componentTypeMask |= JW_JID_LOCALPART;
    }

    jidstrLen += normalizedDomainLen;
    componentTypeMask |= JW_JID_DOMAIN;

    if (NULL != normalizedResource)
    {
        assert(0 < normalizedResourceLen);

        jidstrLen += normalizedResourceLen + 1;
        componentTypeMask |= JW_JID_RESOURCE;
    }

    // allocate jid state
    jw_jid *allocatedJid = jw_data_malloc(sizeof(_jw_jid)+jidstrLen+1);
    if (NULL == allocatedJid)
    {
        JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
        return false;
    }

    // combine elements into jidstr
    uint8_t * curPtr = allocatedJid->str;
    if (NULL != normalizedLocalpart)
    {
        memcpy(curPtr, normalizedLocalpart, normalizedLocalpartLen);
        curPtr += normalizedLocalpartLen;
        *curPtr = '@';
        ++curPtr;
    }

    memcpy(curPtr, normalizedDomain, normalizedDomainLen);
    curPtr += normalizedDomainLen;

    if (NULL != normalizedResource)
    {
        *curPtr = '/';
        ++curPtr;
        memcpy(curPtr, normalizedResource, normalizedResourceLen);
        curPtr += normalizedResourceLen;
    }
    *curPtr = '\0';

    // let _create_jid do the rest
    return _create_jid(ctx, allocatedJid, allocatedJid->str, jidstrLen,
                       componentTypeMask, normalizedLocalpartLen,
                       normalizedDomainLen, normalizedResourceLen, jid, err);
}

/**
 * Public API workhorse.  Will enforce public API requirements.  Arguments are
 * not assumed to be normalized.  Creation is only done if ctx is non-NULL.
 * Otherwise, we just go through the motions and return whether we /would/ have
 * created the jid.
 */
static bool _create_by_parts(jw_jid_ctx     *ctx,
                             const uint8_t *jidstr,
                             size_t         jidstrLen,
                             const uint8_t *localpart,
                             size_t         localpartLen,
                             const uint8_t *domain,
                             size_t         domainLen,
                             const uint8_t *resource,
                             size_t         resourceLen,
                             jw_jid        **jid,
                             jw_err        *err)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    // ensure required elements exist
    if (NULL == domain || 0 == domainLen)
    {
        // TODO: log reason for error
        JABBERWERX_ERROR(err, JW_ERR_INVALID_ARG);
        return false;
    }

    // ensure no element is greater than the maximum allowed size
    if (NULL != localpart && MAX_LEN_INCOMING_STRING < localpartLen)
    {
        // TODO: log reason for error
        JABBERWERX_ERROR(err, JW_ERR_INVALID_ARG);
        return false;
    }
    if (MAX_LEN_INCOMING_STRING < domainLen)
    {
        // TODO: log reason for error
        JABBERWERX_ERROR(err, JW_ERR_INVALID_ARG);
        return false;
    }
    if (NULL != resource && MAX_LEN_INCOMING_STRING < resourceLen)
    {
        // TODO: log reason for error
        JABBERWERX_ERROR(err, JW_ERR_INVALID_ARG);
        return false;
    }

    // normalize as necessary.  if not normalizing (because the string is
    // already normalized), just check length
    bool           isAlreadyNormalized = true;
    jw_jid_part    componentTypeMask = 0;
    jw_jid_part    componentTypes[3];
    const uint8_t *unnormalizedComponents[3];
    size_t         unnormalizedComponentLens[3];
    uint8_t        normalizationBufs[3][MAX_LEN_COMPONENT+1];
    uint8_t       *normalizedComponents[3];
    size_t         normalizedComponentLens[3];

    componentTypes[0] = JW_JID_LOCALPART;
    unnormalizedComponents[0] = localpart;
    unnormalizedComponentLens[0] = localpartLen;
    componentTypes[1] = JW_JID_DOMAIN;
    unnormalizedComponents[1] = domain;
    unnormalizedComponentLens[1] = domainLen;
    componentTypes[2] = JW_JID_RESOURCE;
    unnormalizedComponents[2] = resource;
    unnormalizedComponentLens[2] = resourceLen;

    int componentIdx;
    for (componentIdx = 0; 3 > componentIdx; ++componentIdx)
    {
        const uint8_t * unnormalizedComponent =
                unnormalizedComponents[componentIdx];

        if (NULL != unnormalizedComponent)
        {
            componentTypeMask |= componentTypes[componentIdx];
        }

        size_t unnormalizedComponentLen =
                unnormalizedComponentLens[componentIdx];
        if (_is_normalized_ascii(unnormalizedComponent,
                                 unnormalizedComponentLen))
        {
            // check length
            if (MAX_LEN_COMPONENT < unnormalizedComponentLen)
            {
                // TODO: log reason for error
                JABBERWERX_ERROR(err, JW_ERR_INVALID_ARG);
                return false;
            }

            normalizedComponents[componentIdx] =
                    (uint8_t *)unnormalizedComponent;
            normalizedComponentLens[componentIdx] = unnormalizedComponentLen;
        }
        else
        {
            if (!_normalize(
                    componentTypes[componentIdx], unnormalizedComponent,
                    unnormalizedComponentLen,
                    normalizationBufs[componentIdx], MAX_LEN_COMPONENT+1,
                    &normalizedComponentLens[componentIdx], err))
            {
                return false;
            }

            normalizedComponents[componentIdx] =
                    normalizationBufs[componentIdx];
            isAlreadyNormalized = false;
        }
    }

    if (!_validate_localpart(normalizedComponents[0],
                             normalizedComponentLens[0], err))
    {
        return false;
    }

    if (!_validate_domain(
            normalizedComponents[1], normalizedComponentLens[1], err))
    {
        return false;
    }

    if (NULL != ctx)
    {
        if (isAlreadyNormalized && NULL != jidstr)
        {
            return _create_jid(ctx, NULL, jidstr, jidstrLen,
                               componentTypeMask,
                               localpartLen, domainLen, resourceLen, jid, err);
        }

        if (!_create_jid_from_normalized_parts(ctx,
                        normalizedComponents[0], normalizedComponentLens[0],
                        normalizedComponents[1], normalizedComponentLens[1],
                        normalizedComponents[2], normalizedComponentLens[2],
                        jid, err))
        {
            return false;
        }
    }

    return true;
}

/**
 * Logic for jw_jid_create() and jw_jid_valid().  Jids are only created and
 * refcounts are only modified if ctx and jid are non-NULL.
 */
static bool _create_or_validate_jid(jw_jid_ctx     *ctx,
                                    const uint8_t *jidstr,
                                    jw_jid        **jid,
                                    jw_err        *err)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    // parse into parts
    size_t         jidstrLen;
    const uint8_t *localpart;
    size_t         localpartLen;
    const uint8_t *domain;
    size_t         domainLen;
    const uint8_t *resource;
    size_t         resourceLen;
    if (!_parse_jid(jidstr, &jidstrLen, &localpart, &localpartLen,
                    &domain, &domainLen, &resource, &resourceLen, err))
    {
        return false;
    }

    // create from parsed parts
    return _create_by_parts(ctx, jidstr, jidstrLen,
        localpart, localpartLen, domain, domainLen, resource, resourceLen,
        jid, err);
}


///////////////////////////////////////////////////////////////////////////////
//
// public API
//

JABBERWERX_API bool jw_jid_context_create(size_t      bucket_count,
                                          jw_jid_ctx **ctx,
                                          jw_err     *err)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(NULL != ctx);

    jw_jid_ctx *context = jw_data_malloc(sizeof(_jw_jid_ctx));
    if (NULL == context)
    {
        JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
        return false;
    }

    // pool is for client use for onDestroy callbacks; don't use pages
    if (!jw_pool_create(0, &context->pool, err))
    {
        jw_data_free(context);
        return false;
    }

    if (0 == bucket_count)
    {
        bucket_count = DEFAULT_JID_BUCKET_COUNT;
    }

    if (!jw_htable_create(bucket_count, jw_str_hashcode, jw_str_compare,
                         &context->jids, err))
    {
        jw_pool_destroy(context->pool);
        jw_data_free(context);
        return false;
    }

    *ctx = context;
    return true;
}

JABBERWERX_API void jw_jid_context_destroy(jw_jid_ctx *ctx)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(NULL != ctx);

    // this pool_destroy triggers any context cleanup listeners, do this
    // before destroying the jids as they may be destroyed in a cleaner
    jw_pool_destroy(ctx->pool);

    // destroy cached jids and free context
    jw_htable_destroy(ctx->jids);
    jw_data_free(ctx);
}

JABBERWERX_API void jw_jid_context_htable_cleaner(bool replace,
                                                  bool destroy_key,
                                                  void *key,
                                                  void *data)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    UNUSED_PARAM(replace);
    UNUSED_PARAM(destroy_key);
    UNUSED_PARAM(key);

    jw_jid_context_destroy((jw_jid_ctx*)data);
}

JABBERWERX_API jw_pool *jw_jid_context_get_pool(jw_jid_ctx *ctx)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(NULL != ctx);
    return ctx->pool;
}

JABBERWERX_API bool jw_jid_create(jw_jid_ctx  *ctx,
                                  const char *jidstr,
                                  jw_jid     **jid,
                                  jw_err     *err)
{
    JW_LOG_TRACE_FUNCTION("jidstr='%s'", jidstr);

    assert(NULL != ctx);
    assert(NULL != jid);

    if (!jidstr)
    {
        JABBERWERX_ERROR(err, JW_ERR_INVALID_ARG);
        return false;
    }

    // if we have this jidstr cached, we're done
    jw_jid *retjid = jw_htable_get(ctx->jids, jidstr);
    if (NULL != retjid)
    {
        retjid->refcount++;
        *jid = retjid;
        return true;
    }

    return _create_or_validate_jid(ctx, (const uint8_t *)jidstr, jid, err);
}

JABBERWERX_API bool jw_jid_create_by_parts(jw_jid_ctx  *ctx,
                                           const char *localpart,
                                           const char *domainpart,
                                           const char *resourcepart,
                                           jw_jid     **jid,
                                           jw_err     *err)
{
    JW_LOG_TRACE_FUNCTION("localpart='%s'; domainpart='%s'; resourcepart='%s'",
                          localpart, domainpart, resourcepart);

    assert(NULL != ctx);

    size_t localpartLen = jw_strlen(localpart);
    size_t domainLen    = jw_strlen(domainpart);
    size_t resourceLen  = jw_strlen(resourcepart);

    // NULL out 0-length strings
    return _create_by_parts(ctx, NULL, 0,
        localpartLen ? (const uint8_t *)localpart : NULL, localpartLen,
        domainLen ? (const uint8_t *)domainpart : NULL, domainLen,
        resourceLen ? (const uint8_t *)resourcepart : NULL, resourceLen,
        jid, err);
}

JABBERWERX_API jw_jid *jw_jid_copy(jw_jid *jid)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(NULL != jid);
    assert(NULL != jid->str);

    ++jid->refcount;
    return jid;
}

JABBERWERX_API void jw_jid_destroy(jw_jid *jid)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(NULL != jid);
    assert(NULL != jid->str);
    assert(0 < jid->refcount);

    // decrement the refcount
    --jid->refcount;

    // if the refcount reaches 0, clean up
    if (0 == jid->refcount)
    {
        // if this is not a bare jid, decrement the refcount on the bare JID.
        if (!_is_bare_jid(jid))
        {
            jw_jid_destroy(jid->bareJid);
            // belt + suspenders, make sure nobody uses the bareJid, in case
            // this was the last reference and it got deleted
            jid->bareJid = NULL;
        }

        // remove ourselves from the hashtable, which frees the jid
        jw_htable_remove(jid->ctx->jids, jid->str);
    }
}

JABBERWERX_API jw_jid_ctx *jw_jid_get_context(jw_jid *jid)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(NULL != jid);
    assert(NULL != jid->ctx);

    return jid->ctx;
}

JABBERWERX_API bool jw_jid_import(jw_jid_ctx *ctx,
                                  jw_jid     *jid,
                                  jw_jid    **cpy,
                                  jw_err    *err)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(NULL != jid);

    return _create_jid(ctx, NULL, jid->str, 0, jid->componentsMask,
        jid->localpart ? strlen(jw_jid_get_localpart(jid)) : 0,
        strlen(jw_jid_get_domain(jid)),
        jid->resource ? strlen(jw_jid_get_resource(jid)) : 0, cpy, err);
}

JABBERWERX_API bool jw_jid_valid(const char* jidstr)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    jw_err err;
    return _create_or_validate_jid(NULL, (const uint8_t *)jidstr, NULL, &err);
}

JABBERWERX_API const char* jw_jid_get_localpart(jw_jid *jid)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(NULL != jid);
    return (const char *)jid->localpart;
}

JABBERWERX_API const char* jw_jid_get_domain(jw_jid *jid)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(NULL != jid);
    const char * domain = (const char *)jid->domain;
    assert(NULL != domain);
    return domain;
}

JABBERWERX_API const char* jw_jid_get_resource(jw_jid *jid)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(NULL != jid);
    return (const char *)jid->resource;
}

JABBERWERX_API const char* jw_jid_get_bare(jw_jid *jid)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(NULL != jid);

    if (!_is_bare_jid(jid))
    {
        // get the full jid's bare jid
        jid = jid->bareJid;
        assert(NULL != jid);
    }

    const char * bareJidStr = (const char *)jid->str;
    assert(NULL != bareJidStr);
    return bareJidStr;
}

JABBERWERX_API const char* jw_jid_get_full(jw_jid *jid)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(NULL != jid);
    assert(NULL != jid->str);

    return (const char *)jid->str;
}

JABBERWERX_API jw_jid *jw_jid_get_bare_jid(jw_jid *jid)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(NULL != jid);

    if (!_is_bare_jid(jid))
    {
        // get the full jid's bare jid
        jid = jid->bareJid;
        assert(NULL != jid);
    }

    ++jid->refcount;
    return jid;
}

JABBERWERX_API int jw_jid_cmp(jw_jid *lhs, jw_jid *rhs)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    // shortcut if same instance or both NULL
    int result = lhs - rhs;

    if (result != 0)
    {
        // check for either jid NULLs, part getters expect non NULL
        result = (lhs == NULL ? -1 : (rhs == NULL ? 1 : 0));

        // compare domain then localpart then resource. NULL < !NULL
        if (result == 0)
        {
            result = jw_strcmp(jw_jid_get_domain(lhs), jw_jid_get_domain(rhs));

            if (result == 0)
            {
                result = jw_strcmp(jw_jid_get_localpart(lhs),
                                   jw_jid_get_localpart(rhs));

                if (result == 0)
                {
                    result = jw_strcmp(jw_jid_get_resource(lhs),
                                       jw_jid_get_resource(rhs));
                }
            }
        }
    }
    return result;
}


static bool _jw_jid_escape(const char * unescapedLocalpart,
                    char ** escapedLocalpart,
                    size_t * escapedLocalpartLen, jw_err * err)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(NULL != unescapedLocalpart);
    assert(NULL != escapedLocalpart);
    assert(NULL != escapedLocalpartLen);

    size_t unescIdx = 0;
    size_t unescLen = strlen(unescapedLocalpart);
    size_t escLen = 0;
    char * result = NULL;

    // precalculate required length
    for (unescIdx = 0; unescLen > unescIdx; ++unescIdx)
    {
        switch(unescapedLocalpart[unescIdx])
        {
        case ' ': case '\"': case '&': case '\'': case '/':
        case ':':  case '<': case '>': case '@':
            escLen += 2;
            break;
        case '\\':
            // we need to peek forward; only escape backslash when it's
            // preceding a valid escape sequence
            // TODO: what about capital hex number-letters?
            if ((0 == jw_strncmp(&unescapedLocalpart[unescIdx+1], "20", 2)) ||
                (0 == jw_strncmp(&unescapedLocalpart[unescIdx+1], "22", 2)) ||
                (0 == jw_strncmp(&unescapedLocalpart[unescIdx+1], "26", 2)) ||
                (0 == jw_strncmp(&unescapedLocalpart[unescIdx+1], "27", 2)) ||
                (0 == jw_strncmp(&unescapedLocalpart[unescIdx+1], "2f", 2)) ||
                (0 == jw_strncmp(&unescapedLocalpart[unescIdx+1], "3a", 2)) ||
                (0 == jw_strncmp(&unescapedLocalpart[unescIdx+1], "3c", 2)) ||
                (0 == jw_strncmp(&unescapedLocalpart[unescIdx+1], "3e", 2)) ||
                (0 == jw_strncmp(&unescapedLocalpart[unescIdx+1], "40", 2)) ||
                (0 == jw_strncmp(&unescapedLocalpart[unescIdx+1], "5c", 2))
               )
            {
                escLen += 2;
            }
            break;

        default:
            break;
        }

        ++escLen;
    }

    result = jw_data_malloc(escLen + 1);
    if (NULL == result)
    {
        JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
        return false;
    }

    // set output vars
    *escapedLocalpart = result;
    *escapedLocalpartLen = escLen;

    if (unescLen == escLen)
    {
        // nothing needs to be escaped -- just copy input to output
        memcpy(result, unescapedLocalpart, unescLen+1);
        return true;
    }

    // write escaped string
    size_t escIdx = 0;
    unescIdx = 0;
    for (; unescLen > unescIdx; ++unescIdx)
    {
        switch(unescapedLocalpart[unescIdx])
        {
        case ' ':
            result[escIdx++] = '\\';
            result[escIdx++] = '2';
            result[escIdx++] = '0';
            break;
        case '\"':
            result[escIdx++] = '\\';
            result[escIdx++] = '2';
            result[escIdx++] = '2';
            break;
        case '&':
            result[escIdx++] = '\\';
            result[escIdx++] = '2';
            result[escIdx++] = '6';
            break;
        case '\'':
            result[escIdx++] = '\\';
            result[escIdx++] = '2';
            result[escIdx++] = '7';
            break;
        case '/':
            result[escIdx++] = '\\';
            result[escIdx++] = '2';
            result[escIdx++] = 'f';
            break;
        case ':':
            result[escIdx++] = '\\';
            result[escIdx++] = '3';
            result[escIdx++] = 'a';
            break;
        case '<':
            result[escIdx++] = '\\';
            result[escIdx++] = '3';
            result[escIdx++] = 'c';
            break;
        case '>':
            result[escIdx++] = '\\';
            result[escIdx++] = '3';
            result[escIdx++] = 'e';
            break;
        case '@':
            result[escIdx++] = '\\';
            result[escIdx++] = '4';
            result[escIdx++] = '0';
            break;
        case '\\':
            // we need to peek forward; only escape backslash when it's
            // preceding a valid escape sequence
            // TODO: what about capital hex letters?
            if ((0 == jw_strncmp(&unescapedLocalpart[unescIdx+1], "20", 2)) ||
                (0 == jw_strncmp(&unescapedLocalpart[unescIdx+1], "22", 2)) ||
                (0 == jw_strncmp(&unescapedLocalpart[unescIdx+1], "26", 2)) ||
                (0 == jw_strncmp(&unescapedLocalpart[unescIdx+1], "27", 2)) ||
                (0 == jw_strncmp(&unescapedLocalpart[unescIdx+1], "2f", 2)) ||
                (0 == jw_strncmp(&unescapedLocalpart[unescIdx+1], "3a", 2)) ||
                (0 == jw_strncmp(&unescapedLocalpart[unescIdx+1], "3c", 2)) ||
                (0 == jw_strncmp(&unescapedLocalpart[unescIdx+1], "3e", 2)) ||
                (0 == jw_strncmp(&unescapedLocalpart[unescIdx+1], "40", 2)) ||
                (0 == jw_strncmp(&unescapedLocalpart[unescIdx+1], "5c", 2))
               )
            {
                result[escIdx++] = '\\';
                result[escIdx++] = '5';
                result[escIdx++] = 'c';
            }
            else
            {
                result[escIdx++] = unescapedLocalpart[unescIdx];
            }
            break;

        default:
            result[escIdx++] = unescapedLocalpart[unescIdx];
        }
    }
    result[escIdx] = '\0';

    return true;
}

static bool _jw_jid_unescape(const char * escapedLocalpart,
                      char ** unescapedLocalpart,
                      size_t * unescapedLocalpartLen, jw_err * err)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(NULL != escapedLocalpart);
    assert(NULL != unescapedLocalpart);
    assert(NULL != unescapedLocalpartLen);

    size_t escLen = strlen(escapedLocalpart);

    // sacrifice memory efficiency for speed
    // TODO: it would be better to let clients pass in their own buffer so
    // TODO: we don't have to make this tradeoff decision
    char * result = jw_data_malloc(escLen + 1);
    if (NULL == result)
    {
        JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
        return false;
    }

    *unescapedLocalpart = result;

    // if we're smaller than 3 characters it can't be escaped since all escape
    // sequences are three bytes
    if (escLen < 3)
    {
        memcpy(result, escapedLocalpart, escLen+1);
        *unescapedLocalpartLen = escLen;
        return true;
    }

    // walk the input text, unescaping as we go
    size_t unescIdx = 0;
    size_t escIdx = 0;
    for (; escIdx < (escLen - 2); ++escIdx, ++unescIdx)
    {
        // check if this is an escape character
        if (escapedLocalpart[escIdx] == '\\')
        {
            if (0 == jw_strncmp(&escapedLocalpart[escIdx+1], "20", 2))
            {
                result[unescIdx] = ' ';
                escIdx += 2;
            }
            else if (0 == jw_strncmp(&escapedLocalpart[escIdx+1], "22", 2))
            {
                result[unescIdx] = '\"';
                escIdx += 2;
            }
            else if (0 == jw_strncmp(&escapedLocalpart[escIdx+1], "26", 2))
            {
                result[unescIdx] = '&';
                escIdx += 2;
            }
            else if (0 == jw_strncmp(&escapedLocalpart[escIdx+1], "27", 2))
            {
                result[unescIdx] = '\'';
                escIdx += 2;
            }
            else if (0 == jw_strncmp(&escapedLocalpart[escIdx+1], "2f", 2))
            {
                result[unescIdx] = '/';
                escIdx += 2;
            }
            else if (0 == jw_strncmp(&escapedLocalpart[escIdx+1], "3a", 2))
            {
                result[unescIdx] = ':';
                escIdx += 2;
            }
            else if (0 == jw_strncmp(&escapedLocalpart[escIdx+1], "3c", 2))
            {
                result[unescIdx] = '<';
                escIdx += 2;
            }
            else if (0 == jw_strncmp(&escapedLocalpart[escIdx+1], "3e", 2))
            {
                result[unescIdx] = '>';
                escIdx += 2;
            }
            else if (0 == jw_strncmp(&escapedLocalpart[escIdx+1], "40", 2))
            {
                result[unescIdx] = '@';
                escIdx += 2;
            }
            else if (0 == jw_strncmp(&escapedLocalpart[escIdx+1], "5c", 2))
            {
                result[unescIdx] = '\\';
                escIdx += 2;
            }
            else
            {
                result[unescIdx] = escapedLocalpart[escIdx];
            }
        }
        else
        {
            result[unescIdx] = escapedLocalpart[escIdx];
        }
    }

    // finish writing any leftover non-escape sequences
    if (escIdx != escLen)
    {
        result[unescIdx++] = escapedLocalpart[escIdx++];

        if (escIdx != escLen)
        {
            result[unescIdx++] = escapedLocalpart[escIdx++];
        }

        assert(escIdx == escLen);
    }

    result[unescIdx] = '\0';
    *unescapedLocalpartLen = unescIdx;

    return true;
}


// TODO: a new public API function:
// TODO:   bool jw_jid_localpart_needs_escaping(localpart, *escapedLocalpartLen)
// TODO: would help client be more efficient and avoid a useless memory
// TODO: allocation.  the pre-calculated escapedLocalpartLen could be passed
// TODO: into this function or perhaps a user could use it to allocate their
// TODO: own buffer and pass that in.
JABBERWERX_API bool jw_jid_escape_localpart(const char *localpart,
                                            char      **result,
                                            size_t     *result_len,
                                            jw_err     *err)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(NULL != result);

    char * escapedLocalpart = NULL;
    size_t escapedLocalpartLen = 0;

    if (NULL != localpart)
    {
        if (!_jw_jid_escape(localpart,
                &escapedLocalpart, &escapedLocalpartLen, err))
        {
            return false;
        }
    }

    *result = escapedLocalpart;
    if (result_len)
    {
        *result_len = escapedLocalpartLen;
    }

    return true;
}

JABBERWERX_API bool jw_jid_unescape_localpart(const char *localpart,
                                              char      **result,
                                              size_t     *result_len,
                                              jw_err     *err)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(NULL != result);

    char * unescapedLocalpart = NULL;
    size_t unescapedLocalpartLen = 0;

    if (NULL != localpart)
    {
        if (!_jw_jid_unescape(localpart,
                &unescapedLocalpart, &unescapedLocalpartLen, err))
        {
            return false;
        }
    }

    *result = unescapedLocalpart;
    if (result_len)
    {
        *result_len = unescapedLocalpartLen;
    }

    return true;
}
