/**
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

#include <event2/event.h>
#ifndef JABBERWERX_NO_BOSH
# include <curl/curl.h>
#endif
#include <jabberwerx/util/log.h>
#include "fct.h"
#include "../src/include/log_int.h"


/* Add suites here. Use FCTMF_SUITE_CALL for tests in other files. */
FCT_BGN() {
    FCT_QTEST_BGN(global_setup) {
        // TODO: try removing 3rd party mem init lines periodically to see if
        // TODO:   they have improved.  if we can remove these hacks, update
        // TODO:   the corresponding lines in mem_test's jw_memory_3rdparty fn
        // curl-7.30.0 has a bug where it doesn't return OOM errors properly
        // call this before global init since they can only be set once
#ifndef JABBERWERX_NO_BOSH
        curl_global_init_mem(CURL_GLOBAL_DEFAULT, malloc, free,
                         realloc, strdup, calloc);
#endif
        fct_req(jw_global_init(NULL));
        // libevent doesn't deal well with low memory and breaks our OOM tests
        event_set_mem_functions(NULL, NULL, NULL);
        // this must be set up to bypass jw_data_malloc/jw_data_free since
        // logging is not disturbed by out of memory errors and therefore
        // can let operations succeed where our OOM macros expect them to fail.
        _jw_log_set_memory_funcs(malloc, free);
        jw_log_set_level(JW_LOG_ERROR);
    } FCT_QTEST_END()

    // MUST be the first suite called
    FCTMF_SUITE_CALL(dom_refcount_begin); // see dom_test.c

    FCTMF_SUITE_CALL(basics_test);      // see basics_test.c
    FCTMF_SUITE_CALL(log_test);         // see log_test.c
    FCTMF_SUITE_CALL(error_test);       // see error_test.c
    FCTMF_SUITE_CALL(states_test);      // see states_test.c
    FCTMF_SUITE_CALL(base64_test);      // see base64_test.c
    FCTMF_SUITE_CALL(hex_test);         // see hex_test.c
    FCTMF_SUITE_CALL(htable_test);      // see htable_test.c
    FCTMF_SUITE_CALL(sha1_test);        // see sha1_test.c
    FCTMF_SUITE_CALL(str_test);         // see str_test.c
    FCTMF_SUITE_CALL(jid_test);         // see jid_test.c
    FCTMF_SUITE_CALL(mem_test);         // see mem_test.c
    FCTMF_SUITE_CALL(dom_test);         // see dom_test.c
    FCTMF_SUITE_CALL(parser_test);      // see parser_test.c
    FCTMF_SUITE_CALL(serializer_test);  // see serializer_test.c
    FCTMF_SUITE_CALL(eventing_test);    // see eventing_test.c
    FCTMF_SUITE_CALL(socket_test);      // see socket_test.c
#ifndef JABBERWERX_NO_BOSH
    FCTMF_SUITE_CALL(bosh_conn_test);   // see bosh_conn_test.c
#endif
    FCTMF_SUITE_CALL(bosh_test);        // see bosh_test.c
    FCTMF_SUITE_CALL(workq_test);       // see workq_test.c
    FCTMF_SUITE_CALL(client_test);      // see client_test.c
    FCTMF_SUITE_CALL(tracker_test);     // see tracker_test.c
    FCTMF_SUITE_CALL(sasl_test);        // see sasl_test.c
    FCTMF_SUITE_CALL(tls_test);         // see tls_test.c

    // MUST be the last suite called
    FCTMF_SUITE_CALL(dom_refcount_end); // see dom_test.c

    FCT_QTEST_BGN(global_teardown) {
        jw_global_cleanup();
    } FCT_QTEST_END()
} FCT_END()
