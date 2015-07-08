/**
 * \file
 * \brief
 * XML stream serializer for JabberWerxC.
 *
 * \b NOTE: This API is not thread-safe.  Users MUST ensure access to all
 * instances of a serializer is limited to a single thread.
 *
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

#ifndef JABBERWREX_UTIL_SERIALIZER_H
#define JABBERWREX_UTIL_SERIALIZER_H

#include <event2/buffer.h>
#include "../dom.h"


/** An instance of a xml serializer */
typedef struct _jw_serializer jw_serializer;


#ifdef __cplusplus
extern "C"
{
#endif

/**
 * Creates a new serializer, using the given buffer for output.
 *
 * \b NOTE: The output buffer is not owned by this serializer. The API user
 * MUST free the buffer when finished; jw_serializer_destroy() does not
 * destroy it.
 *
 * This function can generate the following errors (set when returning false):
 * \li \c JW_ERR_NO_MEMORY if the serializer could not be allocated
 *
 * \invariant ser != NULL
 * \invariant out != NULL
 * \param[in] out The evbuffer to serialize to
 * \param[out] ser The new serializer
 * \param[out] err The error information (provide NULL to ignore)
 * \retval bool True if serializer was successfully created, else false.
 */
JABBERWERX_API bool jw_serializer_create(struct evbuffer *out,
                                         jw_serializer  **ser,
                                         jw_err          *err);

/**
 * Destroys the given serializer.
 *
 * \b NOTE: The output buffer associated with ser is not freed when this
 * function is called. The API user MUST destroy the buffer manually.
 *
 * \invariant (ser != NULL)
 * \param[in] ser The serializer to destroy
 */
JABBERWERX_API void jw_serializer_destroy(jw_serializer *ser);

/**
 * Retrieves the output buffer for the given serializer.
 *
 * \b WARNING: Users SHOULD NOT write to this buffer directly without good
 * reason; modifying the buffer directly can result in malformed XML.
 *
 * \invariant ser != NULL
 * \param[in] ser The serializer
 * \retval struct evbuffer * The output buffer
 */
JABBERWERX_API struct evbuffer *jw_serializer_get_output(jw_serializer *ser);

/**
 * Retrieves the current open state of the given serializer. This function
 * returns true after jw_serializer_open() but before jw_serializer_close().
 *
 * \invariant ser != NULL
 * \param[in] ser The serializer
 * \retval bool True if the serializer is open, false otherwise
 */
JABBERWERX_API bool jw_serializer_is_open(jw_serializer *ser);

/**
 * Opens the given serializer, using the given root element. This function
 * writes start tag based on the information from root (expanded name,
 * namespace declarations, and attributes), but does not process any children
 * of root.
 * 
 * \b NOTE: This function does not immediately free all memory allocated. Most
 * will be freed when jw_serializer_destroy() is called, although any memory
 * allocated to the configured buffer will be released when it is destroyed.
 * 
 * This function can generate the following errors (set when returning false):
 * \li \c JW_ERR_NO_MEMORY if memory could not be allocted for serializing.
 * \li \c JW_ERR_INVALID_STATE if the serializer is already open
 *
 * \invariant ser != NULL
 * \invariant root != NULL
 * \invariant jw_dom_get_nodetype(root) == JW_DOM_TYPE_ELEMENT
 * \param[in] ser The serializer
 * \param[in] root The root DOM element
 * \param[out] err The error information (provide NULL to ignore)
 * \retval bool True if node was successfully opened, else false.
 */
JABBERWERX_API bool jw_serializer_write_start(jw_serializer *ser,
                                              jw_dom_node   *root,
                                              jw_err        *err);

/**
 * Processes the given DOM node into this serializer. If this serializer is
 * not open, it will open it using node, then close it before returning
 * successfully.
 *
 * \b NOTE: This function does not immediately free all memory allocated. Most
 * will be freed when jw_serializer_destroy() is called, although any memory
 * allocated to the configured buffer will be released when it is destroyed.
 * 
 * This function can generate the following errors (set when returning false):
 * \li \c JW_ERR_NO_MEMORY if memory could not be allocted for serializing.
 * \li \c JW_ERR_INVALID_ARG if this serializer is not open, and node is
 *                           is not a JW_DOM_TYPE_ELEMENT
 *
 * \invariant ser != NULL
 * \invariant node != NULL
 * \invariant (jw_dom_get_nodetype(node) == JW_DOM_TYPE_ELEMENT) ||
 *            (jw_dom_get_nodetype(node) == JW_DOM_TYPE_TEXT)
 * \param[in] ser The serializer
 * \param[in] node The node DOM node to process
 * \param[out] err The error information (provide NULL to ignore)
 * \retval bool True if node was successfully processed, else false.
 */
JABBERWERX_API bool jw_serializer_write(jw_serializer *ser,
                                        jw_dom_node   *node,
                                        jw_err        *err);

/**
 * Closes the given serializer. This function writes the end tag that matches
 * the root DOM element from jw_serializer_open().
 *
 * \b NOTE: This function does not immediately free all memory allocated. Most
 * will be freed when jw_serializer_destroy() is called, although any memory
 * allocated to the configured buffer will be released when it is destroyed.
 * 
 * This function can generate the following errors (set when returning false):
 * \li \c JW_ERR_NO_MEMORY if memory could not be allocted for serializing.
 * \li \c JW_ERR_INVALID_STATE if the serializer is not open
 *
 * \invariant ser != NULL
 * \param[in] ser The serializer
 * \param[out] err The error information (provide NULL to ignore)
 * \retval bool True if serializer was successfully closed, else false.
 */
JABBERWERX_API bool jw_serializer_write_end(jw_serializer *ser,
                                            jw_err        *err);

/**
 * Serializes the given DOM element into an XML string.
 *
 * \b NOTE: This function allocates the memory for the returned XML string
 * as needed.  Users MUST destroy the memory allocated via jw_data_free(xml),
 * and SHOULD NOT allocate memory for xml directly.
 *
 * This function can generate the following errors (set when returning false):
 * \li \c JW_ERR_NO_MEMORY if there is not enough memory to serialize dom
 *
 * \invariant dom != NULL
 * \invariant jw_dom_get_nodetype(dom) == JW_DOM_TYPE_ELEMENT
 * \invariant xml != NULL
 * \param[in] dom The DOM element to serialize
 * \param[out] xml The XML string for dom
 * \param[out] len If non-NULL, the length of the XML string for dom
 * \param[out] err The error information (provide NULL to ignore)
 * \retval bool true if successful, false otherwise.
 */
JABBERWERX_API bool jw_serialize_xml(jw_dom_node *dom,
                                     char       **xml,
                                     size_t      *len,
                                     jw_err      *err);

/**
 * Serializes the given DOM element into an evbuffer.
 *
 * \b NOTE: The data written to the buffer does NOT include a NULL terminator.
 * 
 * This function can generate the following errors (set when returning false):
 * \li \c JW_ERR_NO_MEMORY if there is not enough memory to serialize dom
 *
 * \invariant dom != NULL
 * \invariant jw_dom_get_nodetype(dom) == JW_DOM_TYPE_ELEMENT
 * \invariant buffer != NULL
 * \param[in] dom The DOM element to serialize
 * \param[out] buffer The evbuffer containing serialized dom
 * \param[out] len The length of the serialized dom
 * \param[out] err The error information (provide NULL to ignore)
 * \retval bool true if successful, false otherwise.
 */
JABBERWERX_API bool jw_serialize_xml_buffer(jw_dom_node *dom,
                                     struct evbuffer    *buffer,
                                     size_t             *len,
                                     jw_err             *err);

#ifdef __cplusplus
}
#endif

#endif /* JABBERWREX_UTIL_SERIALIZER_H */
