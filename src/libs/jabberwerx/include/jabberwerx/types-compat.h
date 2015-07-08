/**
 * \file
 * \brief
 * Deprecated type names for use until transition to the new type names is
 * complete.  This file will eventually be removed.
 *
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

#ifndef JABBERWERX_TYPES_COMPAT_H
#define JABBERWERX_TYPES_COMPAT_H

typedef struct _jw_client                  jw_client_type;
typedef struct _jw_client_status           jw_client_status_type;
typedef struct _jw_client_reconnect_status jw_client_reconnect_status_type;
typedef struct _jw_dom_ctx                 jw_dom_ctx_type;
typedef struct _jw_dom_node                jw_dom_node_type;
typedef struct _jw_event_dispatch_t        jw_event_dispatcher_type;
typedef struct _jw_event_t                 jw_event_type;
typedef struct _jw_event_trigger_t         jw_event_trigger_data_type;
typedef struct _jw_hmac_sha1_ctx_int       jw_hmac_sha1_ctx_type;
typedef struct _jw_hnode                   jw_hnode_type;
typedef struct _jw_htable                  jw_htable_type;
typedef struct _jw_jid_ctx_int             jw_jid_ctx_type;
typedef struct _jw_jid_int                 jw_jid_type;
typedef struct _jw_parser                  jw_parser_type;
typedef struct _jw_pool_int                jw_pool_type;
typedef struct _jw_sasl_factory            jw_sasl_factory_type;
typedef struct _jw_sasl_mech               jw_sasl_mech_type;
typedef struct _jw_sasl_mech_instance      jw_sasl_mech_instance_type;
typedef struct _jw_serializer              jw_serializer_type;
typedef struct _jw_sha1_ctx_int            jw_sha1_ctx_type;
typedef struct _jw_states                  jw_states_type;
typedef struct _jw_states_event_data       jw_states_event_data_type;
typedef struct _jw_stream                  jw_stream_type;
typedef struct _jw_tls_ctx_int             jw_tls_ctx_type;
typedef struct _jw_tls_session_int         jw_tls_session_type;
typedef struct _jw_tracker_t               jw_tracker_type;
typedef struct jw_workq_t                  jw_workq_type;
typedef struct jw_workq_item_t             jw_workq_item_type;

#endif /* JABBERWERX_TYPES_COMPAT_H */
