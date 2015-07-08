/**
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

#ifndef JABBERWERX_TEST_ECHOSRV_CORE_H
#define JABBERWERX_TEST_ECHOSRV_CORE_H


#include <event2/bufferevent.h>
#include <jabberwerx/dom.h>


#ifdef __cplusplus
extern "C"
{
#endif

typedef struct _jw_test_echosrv_core *jw_test_echosrv_core;

typedef enum
{
    JW_ECHOSRV_FEATURE_NONE      = 0,
    //JW_ECHOSRV_FEATURE_TLS       = 1,
    JW_ECHOSRV_FEATURE_SM        = 2,
    JW_ECHOSRV_FEATURE_SM_RESUME = 4
} jw_test_echosrv_features;

/**
 * returns whether the command was handled successfully.  reply stanza should
 * be returned in *reply.
 */
typedef bool (*_cmd_handler_fn)(jw_dom_node  *stanza,
                                const char   *cmd,
                                jw_dom_node  *cmd_data,
                                jw_dom_node **reply,
                                void         *arg,
                                jw_err       *err);

#define JW_ECHOSRV_CMD_ECHO  "echo"
#define JW_ECHOSRV_CMD_SEND  "send"

/**
 * Create an echo server logic core for a single client.  Be aware that
 * echosrv_core uses jw_data_malloc and jw_data_free internally, and may be
 * affected if these functions are redefined.
 *
 * No optional features are enabled by default.  Call
 * _jw_test_echosrv_core_feature_ctrl() to enable/require specific features.
 *
 * This function can generate the following errors (set when returning false):
 * \li \c JW_ERR_NO_MEMORY if the internal state could not be allocated
 *
 * \invariant echosrv_core != NULL
 * \param[out] echosrv_core The newly created echo server core.
 * \param[out] err The error information (provide NULL to ignore)
 * \retval bool true if the echo server core was created successfully.
 */
bool _jw_test_echosrv_core_create(jw_test_echosrv_core *echosrv_core,
                                  jw_err               *err);

/**
 * Destroy the echo server core.
 *
 * \invariant echosrv_core != NULL
 * \param[in] echosrv_core The echo server core to clean up.
 */
void _jw_test_echosrv_core_destroy(jw_test_echosrv_core echosrv_core);

/**
 * Sets the command handler for unrecognized commands.  Set to NULL to remove
 * any current handler.
 *
 * \invariant echosrv_core != NULL
 * \param[in] echosrv_core The echo server core.
 * \param[in] handler_fn the command handler callback.
 * \param[in] arg the opaque argument passed to the handler_fn callback.
 */
void _jw_test_echosrv_core_set_cmd_handler(jw_test_echosrv_core echosrv_core,
                                           _cmd_handler_fn      handler_fn,
                                           void                *arg);

/**
 * Sets which features are enabled and which features are required.  This
 * function must be called before any data is processed if it is to have any
 * effect.  Any undefined bits in the mask parameters are ignored.
 *
 * This function can generate the following errors (set when returning false):
 * \li \c JW_ERR_NO_MEMORY if the internal state could not be allocated
 *
 * \invariant echosrv_core != NULL
 * \param[in] echosrv_core The echo server core
 * \param[in] feature the mask of features to enable/disable
 * \param[in] enabled_features_mask a mask of features to enable; features not
 *                    enabled in the mask will be disabled if they were enabled
 * \param[in] required_features_mask a mask of features to require; features not
 *                    set in either this mask or in enabled_features_mask will
 *                    be set as not required.  I.e. a feature must be set in
 *                    both masks to be effectively required.
 * \param[out] err The error information (provide NULL to ignore)
 * \retval bool true if the feature properties were successfully set
 */
bool _jw_test_echosrv_core_feature_ctrl(
                        jw_test_echosrv_core     echosrv_core,
                        jw_test_echosrv_features enabled_features_mask,
                        jw_test_echosrv_features required_features_mask,
                        jw_err                  *err);

/**
 * Sets the stream ID the echosrv core will return in the features clause.
 *
 * \invariant echosrv_core != NULL
 * \invariant streamId != NULL
 * \invariant strlen(streamId) > 0
 * \param[in] echosrv_core The echo server.
 * \param[in] streamId The string to return as the stream ID.  Do not change
 *                     the contents of this string until the echosrv core is
 *                     destroyed.
 */
void _jw_test_echosrv_core_set_stream_id(jw_test_echosrv_core echosrv_core,
                                         const char          *streamId);

/**
 * Sets the bind jid
 *
 * \invariant echosrv_core != NULL
 * \invariant bind_jid != NULL
 * \invariant strlen(bind_jid) > 0
 * \param[in] echosrv_core The echo server core.
 * \param[in] bind_jid The full jid string to return as the <jid> of a bind
 *                     result stream ID.
 */
void _jw_test_echosrv_core_set_bind_jid(jw_test_echosrv_core echosrv_core,
                                        const char          *bind_jid);

/**
 * Submits a request to the server core logic and retrieves the response.
 *
 * Various "command" elements may be included as a child of any element that
 * change how the core logic responds to that element.  Use the appropriate
 * helper functions for adding command elements.  If no command element is
 * associated with an incoming element, the default behavior (after the
 * connection sequence) is to reverse the from and to attributes of the element
 * and echo the element back to the response buffer.
 *
 * \invariant echosrv_core != NULL
 * \invariant req != NULL
 * \param[in] echosrv_core The echo server.
 * \param[in] req An evbuffer containing the request stanza(s) and possibly
 *                an appended command stanza.
 * \param[in] resp If non-NULL, the response stanza(s) will be added to the
 *                 passed evbuffer.
 * \param[out] err The error information (provide NULL to ignore)
 */
bool _jw_test_echosrv_core_submit(
                        jw_test_echosrv_core echosrv_core,
                        struct evbuffer     *req,
                        struct evbuffer     *resp,
                        jw_err              *err);

/*
 * Adds commands to stanza elements to facilitate remote control of the test
 * echo server.  This function will create a command element (using the given
 * element's context) and attach it to the given element, which can then be
 * submitted to the echosrv core logic for processing.  Keep in mind that
 * attaching commands to connection sequence elements may prevent the echosrv
 * core logic from processing further elements correctly.
 *
 * At this time, the recognized commands are:
 *  JW_ECHOSRV_CMD_ECHO - This is the default command if no other is specified.
 *       It just reverses the 'from' and 'to' attributes and echos the element
 *       it is attached to back to the response stream.
 *  JW_ECHOSRV_CMD_SEND - This uses the given cmd_data element as the next
 *       response instead of whatever would normally be sent/echoed.
 *
 * Unrecognized commands are treated as CMD_ECHO.
 *
 * \param[in] element the element to attach a command to; can be NULL
 * \param[in] cmd the type of command to create; can be NULL
 * \param[in] cmd_data any additional data that the given cmd makes use of; can
 *              be NULL
 * \param[out] err The error information (provide NULL to ignore)
 * \retval bool true if successful; otherwise false.  If element or cmd is NULL
 *   or empty, then nothing will be created or attached but the function will
 *   return true.
 */
bool _jw_test_echosrv_core_add_command(
                        jw_dom_node *element,
                        const char  *cmd,
                        jw_dom_node *cmd_data,
                        jw_err      *err);

/*
 * Removes a command node from the specified element, if any exist.
 *
 * \invariant element != NULL
 * \param[in] element the element to remove a command from
 */
void _jw_test_echosrv_core_remove_command(jw_dom_node *element);

#ifdef __cplusplus
}
#endif

#endif  // JABBERWERX_TEST_ECHOSRV_CORE_H
