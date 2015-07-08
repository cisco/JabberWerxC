/**
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

#include "fct.h"

#include <string.h>
#include <jabberwerx/basics.h>

FCTMF_SUITE_BGN(error_test)
{
    FCT_TEST_BGN(jw_error_message)
    {
        const char *msg;
        msg = jw_err_message(JW_ERR_NONE);
        fct_chk_eq_str(msg, "no error");
        msg = jw_err_message(JW_ERR_INVALID_ARG);
        fct_chk_eq_str(msg, "invalid argument");
        msg = jw_err_message(JW_ERR_INVALID_STATE);
        fct_chk_eq_str(msg, "invalid state");
        msg = jw_err_message(JW_ERR_NO_MEMORY);
        fct_chk_eq_str(msg, "out of memory");
        msg = jw_err_message(JW_ERR_OVERFLOW);
        fct_chk_eq_str(msg, "buffer overflow");
        msg = jw_err_message(JW_ERR_SOCKET_CONNECT);
        fct_chk_eq_str(msg, "socket connect failure");
        msg = jw_err_message(JW_ERR_BAD_FORMAT);
        fct_chk_eq_str(msg, "bad data format");
        msg = jw_err_message(JW_ERR_PROTOCOL);
        fct_chk_eq_str(msg, "protocol error");
        msg = jw_err_message(JW_ERR_TIMEOUT);
        fct_chk_eq_str(msg, "timed out");
        msg = jw_err_message(JW_ERR_NOT_AUTHORIZED);
        fct_chk_eq_str(msg, "not authorized");
        msg = jw_err_message(JW_ERR_USER);
        fct_chk_eq_str(msg, "user-defined error");
    } FCT_TEST_END()
    
    FCT_TEST_BGN(jw_error_macro)
    {
        jw_err  *err_ctx;
        
        err_ctx = (jw_err *)malloc(sizeof(jw_err));
        JABBERWERX_ERROR(err_ctx, JW_ERR_INVALID_ARG);
        fct_chk_eq_int(err_ctx->code, JW_ERR_INVALID_ARG);
        fct_chk_eq_str(err_ctx->message, "invalid argument");
        fct_chk(err_ctx->function != NULL);
        fct_chk(err_ctx->file != NULL);
        fct_chk(err_ctx->line != 0);
        
        memset(err_ctx, 0, sizeof(jw_err));
        JABBERWERX_ERROR(err_ctx, JW_ERR_INVALID_STATE);
        fct_chk_eq_int(err_ctx->code, JW_ERR_INVALID_STATE);
        fct_chk_eq_str(err_ctx->message, "invalid state");
        fct_chk(err_ctx->function != NULL);
        fct_chk(err_ctx->file != NULL);
        fct_chk(err_ctx->line != 0);

        memset(err_ctx, 0, sizeof(jw_err));
        JABBERWERX_ERROR(err_ctx, JW_ERR_NO_MEMORY);
        fct_chk_eq_int(err_ctx->code, JW_ERR_NO_MEMORY);
        fct_chk_eq_str(err_ctx->message, "out of memory");
        fct_chk(err_ctx->function != NULL);
        fct_chk(err_ctx->file != NULL);
        fct_chk(err_ctx->line != 0);

        memset(err_ctx, 0, sizeof(jw_err));
        JABBERWERX_ERROR(err_ctx, JW_ERR_OVERFLOW);
        fct_chk_eq_int(err_ctx->code, JW_ERR_OVERFLOW);
        fct_chk_eq_str(err_ctx->message, "buffer overflow");
        fct_chk(err_ctx->function != NULL);
        fct_chk(err_ctx->file != NULL);
        fct_chk(err_ctx->line != 0);

        memset(err_ctx, 0, sizeof(jw_err));
        JABBERWERX_ERROR(err_ctx, JW_ERR_SOCKET_CONNECT);
        fct_chk_eq_int(err_ctx->code, JW_ERR_SOCKET_CONNECT);
        fct_chk_eq_str(err_ctx->message, "socket connect failure");
        fct_chk(err_ctx->function != NULL);
        fct_chk(err_ctx->file != NULL);
        fct_chk(err_ctx->line != 0);

        memset(err_ctx, 0, sizeof(jw_err));
        JABBERWERX_ERROR(err_ctx, JW_ERR_BAD_FORMAT);
        fct_chk_eq_int(err_ctx->code, JW_ERR_BAD_FORMAT);
        fct_chk_eq_str(err_ctx->message, "bad data format");
        fct_chk(err_ctx->function != NULL);
        fct_chk(err_ctx->file != NULL);
        fct_chk(err_ctx->line != 0);

        memset(err_ctx, 0, sizeof(jw_err));
        JABBERWERX_ERROR(err_ctx, JW_ERR_PROTOCOL);
        fct_chk_eq_int(err_ctx->code, JW_ERR_PROTOCOL);
        fct_chk_eq_str(err_ctx->message, "protocol error");
        fct_chk(err_ctx->function != NULL);
        fct_chk(err_ctx->file != NULL);
        fct_chk(err_ctx->line != 0);

        memset(err_ctx, 0, sizeof(jw_err));
        JABBERWERX_ERROR(err_ctx, JW_ERR_TIMEOUT);
        fct_chk_eq_int(err_ctx->code, JW_ERR_TIMEOUT);
        fct_chk_eq_str(err_ctx->message, "timed out");
        fct_chk(err_ctx->function != NULL);
        fct_chk(err_ctx->file != NULL);
        fct_chk(err_ctx->line != 0);
        
        memset(err_ctx, 0, sizeof(jw_err));
        JABBERWERX_ERROR(err_ctx, JW_ERR_USER);
        fct_chk_eq_int(err_ctx->code, JW_ERR_USER);
        fct_chk_eq_str(err_ctx->message, "user-defined error");
        fct_chk(err_ctx->function != NULL);
        fct_chk(err_ctx->file != NULL);
        fct_chk(err_ctx->line != 0);

        memset(err_ctx, 0, sizeof(jw_err));
        JABBERWERX_ERROR(err_ctx, JW_ERR_NONE);
        fct_chk_eq_int(err_ctx->code, JW_ERR_NONE);
        fct_chk_eq_str(err_ctx->message, "no error");
        fct_chk(err_ctx->function != NULL);
        fct_chk(err_ctx->file != NULL);
        fct_chk(err_ctx->line != 0);
        
        free(err_ctx);
        err_ctx = NULL;
        JABBERWERX_ERROR(err_ctx, JW_ERR_NONE);
        fct_chk(1 && "successful NULL-check");
        JABBERWERX_ERROR(err_ctx, JW_ERR_INVALID_ARG);
        fct_chk(1 && "successful NULL-check");
    } FCT_TEST_END()
} FCTMF_SUITE_END()
