/**
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

#include <jabberwerx/basics.h>
#include <jabberwerx/crypto/tls.h>
#include <fct.h>

#ifndef JABBERWERX_TLS_NONE
FCTMF_SUITE_BGN(tls_test)
{
    FCT_TEST_BGN(jw_tls)
    {
    }FCT_TEST_END()
} FCTMF_SUITE_END()
#else
static void _dummy_accept_cb(jw_tls_session *sess, void *arg)
{
    UNUSED_PARAM(arg);
    jw_tls_proceed(sess, true);
}
FCTMF_SUITE_BGN(tls_test)
{
    FCT_TEST_BGN(jw_tls_not_implemented)
    {
        jw_err                  err;
        //dummy some non-null structs to pass asserts
        jw_tls_ctx        *ctx = (jw_tls_ctx *)1;
        jw_stream         *stream = (jw_stream *)1;
        struct bufferevent     *bev;

        fct_chk(!jw_tls_initialize(&err));
        fct_chk_eq_int(JW_ERR_NOT_IMPLEMENTED, err.code);

        fct_chk(!jw_tls_context_create(&ctx, &err));
        fct_chk_eq_int(JW_ERR_NOT_IMPLEMENTED, err.code);

        fct_chk(!jw_tls_filter_stream(ctx, stream, _dummy_accept_cb, &err));
        fct_chk_eq_int(JW_ERR_NOT_IMPLEMENTED, err.code);

        fct_chk(!jw_tls_socket_create(ctx,stream, _dummy_accept_cb, &bev,&err));
        fct_chk_eq_int(JW_ERR_NOT_IMPLEMENTED, err.code);

        fct_chk(!jw_tls_use_cert_chain(ctx, "foo", "bar", &err));
        fct_chk_eq_int(JW_ERR_NOT_IMPLEMENTED, err.code);

    } FCT_TEST_END()
} FCTMF_SUITE_END()
#endif
