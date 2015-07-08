/**
 * \file
 * \brief
 * XMPP Stream parser for JabberWerxC.
 *
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

#ifndef JABBERWERX_UTIL_PARSER_H
#define JABBERWERX_UTIL_PARSER_H

#include <event2/buffer.h>
#include "../dom.h"
#include "../eventing.h"


/** Root closing tag has been parsed */
#define JW_PARSER_EVENT_CLOSED "parserEventClosed"

/** Root open tag has been parsed and is held "open" */
#define JW_PARSER_EVENT_OPEN "parserEventOpened"

/** A first level child of root has been parsed */
#define JW_PARSER_EVENT_ELEMENT "parserEventElement"


/** An instance of an xml parser */
typedef struct _jw_parser jw_parser;


#ifdef __cplusplus
extern "C"
{
#endif

/**
 * Create a new XML parser.
 * Parser may be created as either a "stream" parser or an element
 * parser. A stream parser treats the root element as a
 * special stream element, firing JW_PARSER_OPEN when its
 * open tag is found, JW_PARSER_ELEMENT when each of its first level
 * children are parsed and JW_PARSER_CLOSED when the root
 * element is closed.
 *
 * Non stream parsers do not fire stream open and close events.
 * The root element(s) invokes a JW_PARSER_ELEMENT when it has been
 * completely parsed.
 *
 * This allows jw_parser to be used to continuously parse elements
 * from an XMPP stream and as a stand alone parser for xml fragments.
 *
 * A parser may fire three events; open, element and closed.
 * \li JW_PARSER_EVENT_OPEN will fire when the root's open element has been
 *      parsed.  The parsed stream open element is passed to the event
 * \li JW_PARSER_EVENT_ELEMENT will fire when a child of root has been parsed,
 *      passing the child to the event.
 * \li JW_PARSER_EVENT_CLOSED will fire when a root close is parsed. A NULL is
 *      passed as the element.
 *
 * <b>Note</b> - A non-NULL element will be destroyed by the parser once all
 * callbacks have completed.  The parser may create a new jw_dom_ctx for every
 * element passed through these events.
 *
 * err is set when returning false:
 * \li \c JW_ERR_NO_MEMORY if the parser could not be allocated
 *
 * \invariant parser != NULL
 * \param[in] stream_parser true if parser is a stream parser, false
 *                          creates an element parser.
 * \param[out] parser The new parser
 * \param[out] err The error information (provide NULL to ignore)
 * \retval bool True if parser was successfully created, else false.
 */
JABBERWERX_API bool jw_parser_create(bool        stream_parser,
                                     jw_parser **parser,
                                     jw_err     *err);

/**
 * Destroy the given parser.
 *
 * \invariant parser != NULL
 * \param[in] parser The new parser to destroy
 */
JABBERWERX_API void jw_parser_destroy(jw_parser *parser);

/**
 * Parse the given buffer and fire corresponding events.
 *
 * err is set when returning false:
 * \li \c JW_ERR_INVALID_ARG if buffer results in an xml parse error
 * \li \c JW_ERR_INVALID_STATE if a previous parse error was enccountered.
 * \li \c JW_ERR_NO_MEMORY if the parser could not be allocated
 *
 * If an error occurs during a process call the parser is moved to
 * an invalid state and cannot be used for parsing again. Subsequent
 * calls to jw_parser_process will always return a JW_ERR_INVALID_STATE
 * error. The parser should be destroyed and recreated to continue parsing.
 *
 * \invariant parser != NULL
 * \param[in] parser The parser to use.
 * \param[in] buffer The evbuffer to parse. May be NULL or empty.
 *                   buffer is completely drained on success. Its
 *                   contents are undefined if an error occurred.
 * \param[out] err The error information (provide NULL to ignore)
 * \retval bool True If buffer does not generate an xml parse error.
 */
JABBERWERX_API bool jw_parser_process(jw_parser       *parser,
                                      struct evbuffer *buffer,
                                      jw_err          *err);

/**
 * Stand alone parse of given string
 *
 * Parse the given string into a new jw_dom_node.
 * The parser does not own any
 * new nodes created, the node MUST be freed by the caller.
 * Failure to do so will result in memory leaks.
 *
 * Returns false and sets error if source is bad xml or
 * dom could not be created.
 *
 * err is set when returning false:
 * \li \c JW_ERR_INVALID_ARG if buffer results in an xml parse error
 * \li \c JW_ERR_NO_MEMORY if dom could not be created
 *
 * \invariant parsed_dom != NULL
 * \param[in] source The xml fragment to parse. May be NULL or empty.
 * \param[out] parsed_dom The resultant DOM.
 *                        NULL if source was NULL or empty
 * \param[out] err The error information (provide NULL to ignore)
 * \retval bool True if source could be parsed into dom.
 *
 */
JABBERWERX_API bool jw_parse_xml(const char  *source,
                                jw_dom_node **parsed_dom,
                                jw_err       *err);
/**
 * Parse the given buffer
 *
 * Parse the given buffer into a new jw_dom_node.
 * The parser does not own any
 * new nodes created, the node MUST be freed by the caller.
 * Failure to do so will result in memory leaks.
 *
 * Returns false and sets error if source is bad xml or
 * dom could not be created.
 *
 * err is set when returning false:
 * \li \c JW_ERR_INVALID_ARG if buffer results in an xml parse error
 * \li \c JW_ERR_NO_MEMORY if dom could not be created
 *
 * \invariant parsed_dom != NULL
 * \param[in] buffer The evbuffer to parse. May be NULL or empty.  The buffer
 *                   will be completely drained on success. Its contents are
 *                   undefined if an error occurs.
 *
 * \param[out] parsed_dom The resultant DOM.
 *                        NULL if buffer was NULL or empty
 * \param[out] err The error information (provide NULL to ignore)
 * \retval bool True if buffer could be parsed into dom.
 *
 */
JABBERWERX_API bool jw_parse_xml_buffer(struct evbuffer *buffer,
                                        jw_dom_node    **parsed_dom,
                                        jw_err          *err);
/**
 * Get a parser event.  Returns the event on success and NULL if event is not
 * found.
 * The memory allocated for the event will continue to be owned by the parser.
 *
 * \invariant parser != NULL
 * \invariant name != NULL
 * \invariant *name != '\\0'
 * \param[in] parser The parser owning the event dispatcher.
 * \param[in] name The name of the event.
 * \retval jw_event The found event or NULL if it does not exist.
 */
JABBERWERX_API jw_event *jw_parser_event(jw_parser  *parser,
                                         const char *name);

#ifdef __cplusplus
}
#endif

#endif  /* JABBERWERX_UTIL_PARSER_H */
