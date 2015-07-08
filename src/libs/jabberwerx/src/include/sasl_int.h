/**
 * \file
 * \brief
 * Internal SASL types and functions
 *
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

#ifndef JABBERWERX_SASL_INT_H
#define JABBERWERX_SASL_INT_H

#include <jabberwerx/sasl_mech.h>


#define SASL_URI "urn:ietf:params:xml:ns:xmpp-sasl"
#define SASL_AUTH       "{" SASL_URI "}auth"
#define SASL_SUCCESS    "{" SASL_URI "}success"
#define SASL_FAILURE    "{" SASL_URI "}failure"
#define SASL_CHALLENGE  "{" SASL_URI "}challenge"
#define SASL_RESPONSE   "{" SASL_URI "}response"
#define SASL_MECHANISM_LOCALNAME  "mechanism"
#define SASL_MECHANISM  "{" SASL_URI "}" SASL_MECHANISM_LOCALNAME
#define SASL_MECHANISMS "{" SASL_URI "}mechanisms"

#define SASL_ERR_ABORTED             "{" SASL_URI "}aborted"
#define SASL_ERR_ACCOUNT_DISABLED    "{" SASL_URI "}account-disabled"
#define SASL_ERR_CREDENTIALS_EXPIRED "{" SASL_URI "}credentials-expired"
#define SASL_ERR_ENCRYPTION_REQUIRED "{" SASL_URI "}encryption-required"
#define SASL_ERR_INCORRECT_ENCODING  "{" SASL_URI "}incorrect-encoding"
#define SASL_ERR_INVALID_AUTHZID     "{" SASL_URI "}invalid-authzid"
#define SASL_ERR_INVALID_MECHANISM   "{" SASL_URI "}invalid-mechanism"
#define SASL_ERR_MALFORMED_REQUEST   "{" SASL_URI "}malformed-request"
#define SASL_ERR_MECHANISM_TOO_WEAK  "{" SASL_URI "}mechanism-too-weak"
#define SASL_ERR_NOT_AUTHORIZED      "{" SASL_URI "}not-authorized"
#define SASL_ERR_TEMPORARY_AUTH_FAILURE_LOCALNAME    "temporary-auth-failure"
#define SASL_ERR_TEMPORARY_AUTH_FAILURE \
                                "{" SASL_URI "}" SASL_ERR_TEMPORARY_AUTH_FAILURE_LOCALNAME


#ifdef __cplusplus
extern "C"
{
#endif

struct _jw_sasl_mech
{
    const char           *name;
    jw_sasl_mech_fn_table fn_table;
    jw_sasl_mech          *next; // mechs can only be added to a single factory
};

struct _jw_sasl_mech_instance
{
    jw_sasl_mech *mech;
    uint32_t     step_count;

    jw_sasl_mech_evaluate_complete_fn cur_cb;
    void                             *cur_arg;

    void *data;
};


bool _jw_sasl_mech_sasl_err_to_failure_node(
        jw_sasl_error sasl_err, jw_dom_ctx *ctx, jw_dom_node **node, jw_err *err);


#ifdef __cplusplus
}
#endif

#endif	// JABBERWERX_SASL_INT_H
