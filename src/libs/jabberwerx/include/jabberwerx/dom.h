/**
 * \file
 * \brief
 * Datatypes and functions for representing the Document Object Model (DOM).
 *
 * The naming of elements and attributes within this DOM is based on Clark
 * Notation expanded-names. These names include the namespace and localname
 * of a node within a single string:
 *
 * \li \c "{namespace}localname" (localname + namespace)
 * \li \c "{}localname" (localname + null namespace)
 *
 * \b NOTE: All nodes created within a DOM context, either explicitly or
 * implicitly, are owned by the DOM context. The memory allocated is
 * freed when the context is destroyed via jw_dom_context_destroy().
 *
 * \b NOTE: Unless otherwise stated, any values returned by DOM functions are
 * owned by the DOM context, and MUST NOT be freed directly by the user. The
 * memory is released when the DOM context is destroyed via
 * jw_dom_context_destroy().
 *
 * \b NOTE: This API is not thread-safe.  Users MUST ensure access to all
 * instances of a context and its nodes is limited to a single thread.
 *
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

#ifndef JABBERWERX_DOM_H
#define JABBERWERX_DOM_H

#include "util/mem.h"

    
/** Expanded name for the locale attribute (xml:lang) */
#define JW_DOM_ATTR_XML_LANG "{http://www.w3.org/XML/1998/namespace}lang"


/** Datatype for the DOM context. The DOM context owns all related DOM nodes. */
typedef struct _jw_dom_ctx jw_dom_ctx;

/** Datatype for a DOM node. */
typedef struct _jw_dom_node jw_dom_node;


/** Enumeration of DOM node types. */
typedef enum
{
    /** Attribute node type */
    JW_DOM_TYPE_ATTRIBUTE = 1,
    /** Namespace declaration node type */
    JW_DOM_TYPE_NAMESPACE,
    /** Text node type */
    JW_DOM_TYPE_TEXT,
    /** Element node type */
    JW_DOM_TYPE_ELEMENT
} jw_dom_nodetype;


#ifdef __cplusplus
extern "C"
{
#endif

/**
 * Creates a new DOM context.
 *
 * This function can generate the following errors (set when returning false):
 * \li \c JW_ERR_NO_MEMORY if the context could not be allocated
 *
 * \invariant ctx != NULL
 * \param[out] ctx The DOM context
 * \param[out] err The error information (provide NULL to ignore)
 * \retval bool true if successful, false otherwise.
 */
JABBERWERX_API bool jw_dom_context_create(jw_dom_ctx **ctx, jw_err *err);

/**
 * Decrements the refcount of a DOM context.  If the refcount reaches 0, this
 * function will destroy the context and free all related nodes.
 *
 * \invariant ctx != NULL
 * \param[in] ctx The DOM context
 */
JABBERWERX_API void jw_dom_context_destroy(jw_dom_ctx *ctx);

/**
 * Checks that all of the DOM Contexts that have been created by this program
 * have reached 0 refcount, and have been subsequently freed.  If there are
 * contexts that have not been freed, lots of diagnostic info is logged at the
 * ERROR level.
 *
 * NOTE: This always returns true unless dom.c is compiled with -DDEBUG_REFCOUNT
 *
 * \param[out] err The error information (provide NULL to ignore)
 * \retval bool true if successful, false otherwise.
 */
JABBERWERX_API bool jw_dom_contexts_are_all_free(jw_err *err);

/**
 * Increments the refcount of a DOM context, adding to the number of times
 * jw_dom_context_destroy() must be called before the context is actually
 * destroyed.
 *
 * This function can generate the following errors (set when returning false):
 * \li \c JW_ERR_OVERFLOW if the context has been "retained" so many times that
 * the internal refcount would overflow
 *
 * \invariant ctx != NULL
 * \param[in] ctx The DOM context
 * \param[out] err The error information (provide NULL to ignore)
 * \retval bool true if successful, false otherwise.
 */
JABBERWERX_API bool jw_dom_context_retain(jw_dom_ctx *ctx, jw_err *err);

/**
 * Retrieves the current refcount of a DOM context for debugging purposes.  This
 * function is provided as a convenience for use in tracking down memory leaks
 * in client applications.  It is not intended to be used as a hack for figuring
 * out when jw_dom_context_destroy() should be called.
 *
 * \invariant ctx != NULL
 * \param[in] ctx The DOM context
 * \retval int32_t the reference count of the given context
 */
JABBERWERX_API int32_t jw_dom_context_get_refcount_DEBUG(jw_dom_ctx *ctx);

/**
 * Retrieves the memory pool for the given DOM context.
 *
 * \b NOTE: This pool is owned by the DOM context and MUST NOT be destroyed
 * directly; instead it is destroyed as part of jw_dom_context_destroy().
 *
 * \invariant ctx != NULL
 * \param[in] ctx The DOM context
 * \retval jw_pool The memory pool for ctx
 */
JABBERWERX_API jw_pool *jw_dom_context_get_pool(jw_dom_ctx *ctx);

/**
 * Copies the given DOM node into the given DOM context. If node is already
 * owned by ctx, it is returned as-is.  Otherwise a copy of node is made in
 * the current context, excluding its ancestors.
 *
 * If deep is true, then all descendants of node are imported. Otherwise,
 * only the namespace declarations and attributes are imported.
 *
 * \b NOTE: This function can allocate memory that is not freed until the
 * context is destroyed, even if this function fails (because of memory
 * exhaustion). Currently, the only solution is to destroy the owning
 * context, which also destroys any DOM nodes already created.
 *
 * This function can generate the following errors (set when returning false):
 * \li \c JW_ERR_NO_MEMORY if the node could not be allocated
 *
 * \invariant ctx != NULL
 * \invariant node != NULL
 * \invariant cpy != NULL
 * \param[in] ctx The DOM context
 * \param[in] node The (original) DOM node
 * \param[in] deep true if all descendants of node should be imported
 * \param[out] cpy The imported DOM node
 * \param[out] err The error information (provide NULL to ignore)
 * \retval bool true if successful, false otherwise.
 */
JABBERWERX_API bool jw_dom_import(jw_dom_ctx   *ctx,
                                  jw_dom_node  *node,
                                  bool          deep,
                                  jw_dom_node **cpy,
                                  jw_err       *err);

/**
 * Duplicates the given DOM node in the same DOM context. This function
 * creates a copy of node, excluding its ancestors.
 *
 * If deep is true, then all descendants of node are cloned. Otherwise,
 * only the namespace declarations and attributes are cloned.
 *
 * \b NOTE: This function can allocate memory that is not freed until the
 * context is destroyed, even if this function fails (because of memory
 * exhaustion). Currently, the only solution is to destroy the owning
 * context, which also destroys the original element.
 *
 * This function can generate the following errors (set when returning false):
 * \li \c JW_ERR_NO_MEMORY if the node could not be allocated
 *
 * \invariant node != NULL
 * \invariant cpy != NULL
 * \param[in] node The (original) DOM node
 * \param[in] deep true if all descendants of node should be cloned
 * \param[out] cpy The cloned DOM node
 * \param[out] err The error information (provide NULL to ignore)
 * \retval bool true if successful, false otherwise.
 */
JABBERWERX_API bool jw_dom_clone(jw_dom_node  *node,
                                 bool          deep,
                                 jw_dom_node **cpy,
                                 jw_err       *err);

/**
 * Creates a new DOM element within the given DOM context.
 *
 * \b NOTE: The returned node is owned by the DOM context and MUST NOT be
 * destroyed or freed directly; instead it is destroyed as part of
 * jw_dom_context_destroy().
 *
 * This function can generate the following errors (set when returning false):
 * \li \c JW_ERR_NO_MEMORY if the element could not be allocated
 * \li \c JW_ERR_INVALID_ARG if ename is not a valid expanded-name
 *
 * \invariant ctx != NULL
 * \invariant ename != NULL
 * \invariant elem != NULL
 * \param[in] ctx The DOM context
 * \param[in] ename The expanded-name
 * \param[out] elem The DOM element
 * \param[out] err The error information (provide NULL to ignore)
 * \retval bool true if successful, false otherwise.
 */
JABBERWERX_API bool jw_dom_element_create(jw_dom_ctx   *ctx,
                                          const char   *ename,
                                          jw_dom_node **elem,
                                          jw_err       *err);

/**
 * Creates a new DOM text node within the given DOM context.
 *
 * \b NOTE: The returned node is owned by the DOM context and MUST NOT be
 * destroyed or freed directly; instead it is destroyed as part of
 * jw_dom_context_destroy().
 *
 * This function can generate the following errors (set when returning false):
 * \li \c JW_ERR_NO_MEMORY if the text could not be allocated
 * \li \c JW_ERR_INVALID_ARG if value is not valid UTF-8
 *
 * \invariant ctx != NULL
 * \invariant value != NULL
 * \invariant text != NULL
 * \param[in] ctx The DOM context
 * \param[in] value The text content
 * \param[out] text The DOM text node
 * \param[out] err The error information (provide NULL to ignore)
 * \retval bool true if successful, false otherwise.
 */
JABBERWERX_API bool jw_dom_text_create(jw_dom_ctx   *ctx,
                                       const char   *value,
                                       jw_dom_node **text,
                                       jw_err       *err);

/**
 * Retrieves the DOM context that owns the given DOM node.
 *
 * \invariant node != NULL
 * \param[in] node The DOM node
 * \retval jw_dom_cx The owning DOM context
 */
JABBERWERX_API jw_dom_ctx *jw_dom_get_context(jw_dom_node *node);

/**
 * Retrieves the nodetype for the given DOM node.
 *
 * \invariant node != NULL
 * \param[in] node The DOM node
 * \retval jw_dom_nodetype The nodetype
 */
JABBERWERX_API jw_dom_nodetype jw_dom_get_nodetype(jw_dom_node *node);

/**
 * Retrieves the expanded-name of the given DOM node. The exact syntax
 * of the returned string depends on the type of node:
 * \li \c JW_DOM_TYPE_ATTRIBUTE "{namespace}localname"
 * \li \c JW_DOM_TYPE_NAMESPACE "namespace-prefix"
 * \li \c JW_DOM_TYPE_TEXT      NULL
 * \li \c JW_DOM_TYPE_ELEMENT   "{namespace}localname"
 *
 * \invariant node != NULL
 * \param[in] node The DOM node
 * \retval const char * The expanded-name, or NULL if node does not have a
 *                      name
 */
JABBERWERX_API const char *jw_dom_get_ename(jw_dom_node *node);

/**
 * Retrieves the localname of the given DOM node.
 *
 * \invariant node != NULL
 * \invariant (jw_dom_get_nodetype(node) == JW_DOM_TYPE_ELEMENT) ||
 *            (jw_dom_get_nodetype(node) == JW_DOM_TYPE_ATTRIBUTE)
 * \param[in] node The DOM node
 * \retval const char * The localname
 */
JABBERWERX_API const char *jw_dom_get_localname(jw_dom_node *node);

/**
 * Retrieves the namespace URI of the given DOM node.
 *
 * \invariant node != NULL
 * \invariant (jw_dom_get_nodetype(node) == JW_DOM_TYPE_ELEMENT) ||
 *            (jw_dom_get_nodetype(node) == JW_DOM_TYPE_ATTRIBUTE)
 * \param[in] node The DOM node
 * \retval const char * The namespace URI
 */
JABBERWERX_API const char *jw_dom_get_namespace_uri(jw_dom_node *node);

/**
 * Retrieves the value of the given DOM node.
 *
 * The semantics of what is returned is different for each node type:
 * \li \c JW_DOM_TYPE_ATTRIBUTE the attribute value (unescaped)
 * \li \c JW_DOM_TYPE_NAMESPACE the namespace URI
 * \li \c JW_DOM_TYPE_TEXT the text value (unescaped)
 * \li \c JW_DOM_TYPE_ELEMENT always NULL
 *
 * \invariant node != NULL
 * \param[in] node The DOM node
 * \retval const char * The value of node
 */
JABBERWERX_API const char *jw_dom_get_value(jw_dom_node *node);

/**
 * Retrieves the parent node for the given DOM node.
 *
 * \invariant node != NULL
 * \param[in] node The DOM node
 * \retval jw_dom_node The parent of node, or NULL if none
 */
JABBERWERX_API jw_dom_node *jw_dom_get_parent(jw_dom_node *node);

/**
 * Retrieves the (next) sibling for the given DOM node.
 *
 * \invariant node != NULL
 * \param[in] node The current DOM node
 * \retval jw_dom_node The next DOM node, or NULL if node is the last.
 */
JABBERWERX_API jw_dom_node *jw_dom_get_sibling(jw_dom_node *node);

/**
 * Detaches this DOM node from its parent. This function guarantees
 * that jw_dom_get_parent(node) returns NULL.
 *
 * \b NOTE: The node is still owned by its context, and will be
 * destroyed when the context is destroyed.
 *
 * \invariant node != NULL
 * \param[in] node The DOM node
 */
JABBERWERX_API void jw_dom_detach(jw_dom_node *node);

/**
 * Retrieves the first namespace declaration in the given DOM element.
 *
 * \invariant elem != NULL
 * \invariant jw_dom_get_nodetype(node) == JW_DOM_TYPE_ELEMENT
 * \param[in] elem The DOM element
 * \retval jw_dom_node The first namespace declaration, or NULL if none
 */
JABBERWERX_API jw_dom_node *jw_dom_get_first_namespace(jw_dom_node *elem);

/**
 * Changes or removes the value of the given namespace declaration in the
 * given DOM element. If uri is NULL, the namespace declaration is removed
 * from elem.
 *
 * A namespace prefix may be the empty string ("") or any string that is
 * valid as an element localname.
 *
 * A namespace URI may be any value, including the empty string("").
 *
 * This function can generate the following errors (set when returning false):
 * \li \c JW_ERR_NO_MEMORY if the attribute could not be allocated
 * \li \c JW_ERR_INVALID_ARG if prefix is not a valid namespace prefix
 *
 * \invariant elem != NULL
 * \invariant jw_dom_get_nodetype(elem) == JW_DOM_TYPE_ELEMENT
 * \invariant prefix != NULL
 * \param[in] elem The DOM element
 * \param[in] prefix The namespace's prefix
 * \param[in] uri The namespace's new URI, or NULL to remove
 * \param[out] err The error information (provide NULL to ignore)
 * \retval bool true if successful, false otherwise.
 */
JABBERWERX_API bool jw_dom_put_namespace(jw_dom_node *elem,
                                         const char  *prefix,
                                         const char  *uri,
                                         jw_err      *err);

/**
 * Finds the first namespace URI mapped to the given prefix, starting at the
 * given DOM element. This function will walk the ancenstors of elem until
 * a mapping is found, or there are no more ancestors.
 *
 * \invariant elem != NULL
 * \invariant jw_dom_get_nodetype(elem) == JW_DOM_TYPE_ELEMENT
 * \invariant prefix != NULL
 * \param[in] elem The DOM element
 * \param[in] prefix The namespace prefix
 * \retval const char * The namespace URI for prefix, or NULL if none found.
 */
JABBERWERX_API const char *jw_dom_find_namespace_uri(jw_dom_node *elem,
                                                     const char  *prefix);

/**
 * Finds the first namespace prefix mapped to the given URI, starting at the
 * given DOM element. This function will walk the ancenstors of elem until
 * a mapping is found, or there are no more ancestors.
 *
 * \invariant elem != NULL
 * \invariant jw_dom_get_nodetype(elem) == JW_DOM_TYPE_ELEMENT
 * \invariant uri != NULL
 * \param[in] elem The DOM element
 * \param[in] uri The namespace URI
 * \retval const char * The namespace prefix for uri, or NULL if none found.
 */
JABBERWERX_API const char *jw_dom_find_namespace_prefix(jw_dom_node *elem,
                                                        const char  *uri);

/**
 * Retrieves the first attribute in the given DOM element.
 *
 * \invariant elem != NULL
 * \invariant jw_dom_get_nodetype(node) == JW_DOM_TYPE_ELEMENT
 * \param[in] elem The DOM element
 * \retval jw_dom_node The first attribute in elem, or NULL if none
 */
JABBERWERX_API jw_dom_node *jw_dom_get_first_attribute(jw_dom_node *elem);

/**
 * Retrieves the value of the given attribute in the given DOM element.
 *
 * \invariant elem != NULL
 * \invariant jw_dom_get_nodetype(elem) == JW_DOM_TYPE_ELEMENT
 * \invariant ename != NULL
 * \param[in] elem The DOM element
 * \param[in] ename The attribute's expanded-name
 * \retval const char * The value for the attribute {ename}, or NULL if
 *                      there is no attribute
 */
JABBERWERX_API const char *jw_dom_get_attribute(jw_dom_node *elem,
                                                const char  *ename);

/**
 * Changes or removes the value of the given attribute in the given DOM
 * element. If value is NULL, the attribute is removed from elem.
 *
 * This function can generate the following errors (set when returning false):
 * \li \c JW_ERR_NO_MEMORY if the attribute could not be allocated
 * \li \c JW_ERR_INVALID_ARG if ename is not a valid expanded-name
 *
 * \invariant elem != NULL
 * \invariant jw_dom_get_nodetype(elem) == JW_DOM_TYPE_ELEMENT
 * \invariant ename != NULL
 * \param[in] elem The DOM element
 * \param[in] ename The attribute's expanded-name
 * \param[in] value The attribute's new value, or NULL to remove
 * \param[out] err The error information (provide NULL to ignore)
 * \retval bool true if successful, false otherwise.
 */
JABBERWERX_API bool jw_dom_set_attribute(jw_dom_node *elem,
                                         const char  *ename,
                                         const char  *value,
                                         jw_err      *err);

/**
 * Retrieves the first content node (element or text) for the given DOM node.
 *
 * \invariant elem != NULL
 * \invariant jw_dom_get_nodetype(elem) == JW_DOM_TYPE_ELEMENT
 * \param[in] elem The DOM element
 * \retval jw_dom_node The first content node for elem, or NULL if none.
 */
JABBERWERX_API jw_dom_node *jw_dom_get_first_child(jw_dom_node *elem);

/**
 * Retrieves the first child element in the given DOM element whose name
 * matches ename.
 *
 * The value of ename may be a full expanded-name (e.g."{namespace}localname"),
 * localname-only (e.g. "localname"), or namespace-only (e.g. "{namespace}").
 *
 * \invariant elem != NULL
 * \invariant jw_dom_get_nodetype(elem) == JW_DOM_TYPE_ELEMENT
 * \param[in] elem The DOM element
 * \param[in] ename The expanded-name
 * \retval jd_dom_node The first child element of elem matching ename, or NULL
 *                     if none
 */
JABBERWERX_API jw_dom_node *jw_dom_get_first_element(jw_dom_node *elem,
                                                     const char  *ename);

/**
 * Retrieves the value of the first text node for the given DOM element.
 *
 * \invariant elem != NULL
 * \invariant jw_dom_get_nodetype(elem) == JW_DOM_TYPE_ELEMENT
 * \param[in] elem The DOM element
 * \retval const char * The value of the first child text node, or
 *                      NULL if none
 */
JABBERWERX_API const char *jw_dom_get_first_text(jw_dom_node *elem);

/**
 * Adds the given content node to the given DOM element. The child is first
 * detached before being added to the parent.
 *
 * This function can generate the following errors (set when returning false):
 * \li \c JW_ERR_INVALID_ARG if child == parent
 *
 * \invariant parent != NULL
 * \invariant jw_dom_get_nodetype(parent) == JW_DOM_TYPE_ELEMENT
 * \invariant child != NULL
 * \invariant jw_dom_get_nodetype(child) == JW_DOM_TYPE_ELEMENT ||
 *            jw_dom_get_nodetype(child) == JW_DOM_TYPE_TEXT
 * \invariant jw_dom_get_context(parent) == jw_dom_get_context(child)
 * \param[in] parent The DOM parent element
 * \param[in] child The DOM child element
 * \param[out] err The error information (provide NULL to ignore).
 * \retval bool true if successful, false otherwise.
 */
JABBERWERX_API bool jw_dom_add_child(jw_dom_node *parent,
                                     jw_dom_node *child,
                                     jw_err      *err);

/**
 * Removes the given content (element or text) node from the given DOM element.
 *
 * This function can generate the following errors (set when returning false):
 * \li \c JW_ERR_INVALID_ARG if child == parent, or
 *                           jw_dom_get_parent(child) != parent
 *
 * \invariant parent != NULL
 * \invariant jw_dom_get_nodetype(parent) == JW_DOM_TYPE_ELEMENT
 * \invariant child != NULL
 * \param[in] parent The DOM parent element
 * \param[in] child The DOM child element
 * \param[out] err The error information (provide NULL to ignore)
 * \retval bool true if successful, false otherwise.
 */
JABBERWERX_API bool jw_dom_remove_child(jw_dom_node *parent,
                                        jw_dom_node *child,
                                        jw_err      *err);

/**
 * Removes all children from the given DOM element.  This is a convenience
 * over calling the following:
 * \code
 * itr = jw_dom_get_first_child(elem);
 * while (itr != NULL)
 * {
 *     jw_dom_node cur = itr;
 *     itr = jw_dom_get_sibling(cur);
 *     jw_dom_detach(cur);
 * }
 * \endcode
 *
 * \invariant elem != NULL
 * \param[in] elem The DOM element
 */
JABBERWERX_API void jw_dom_clear_children(jw_dom_node *elem);

#ifdef __cplusplus
}
#endif

#endif /* JABBERWERX_DOM_H */
