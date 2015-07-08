/**
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

#ifndef JABBERWERX_TEST_STANZA_DEFINES_H
#define JABBERWERX_TEST_STANZA_DEFINES_H


#define XMPP_CLIENT_URI "jabber:client"

#define XMPP_CLIENT_IQ       "{" XMPP_CLIENT_URI "}iq"
#define XMPP_CLIENT_PRESENCE "{" XMPP_CLIENT_URI "}presence"
#define XMPP_CLIENT_ERROR    "{" XMPP_CLIENT_URI "}error"

#define XMPP_TLS_URI "urn:ietf:params:xml:ns:xmpp-tls"
#define XMPP_TLS_STARTTLS "{" XMPP_TLS_URI "}starttls"
#define XMPP_TLS_REQUIRED "{" XMPP_TLS_URI "}required"
#define XMPP_TLS_FAILURE  "{" XMPP_TLS_URI "}failure"
#define XMPP_TLS_PROCEED  "{" XMPP_TLS_URI "}proceed"

#define XMPP_SASL_URI "urn:ietf:params:xml:ns:xmpp-sasl"
#define XMPP_SASL_PLAIN "PLAIN"
#define XMPP_SASL_MECHS   "{" XMPP_SASL_URI "}mechanisms"
#define XMPP_SASL_AUTH    "{" XMPP_SASL_URI "}auth"
#define XMPP_SASL_SUCCESS "{" XMPP_SASL_URI "}success"
#define XMPP_SASL_MECH    "{" XMPP_SASL_URI "}mechanism"
#define XMPP_SASL_SUCCESS "{" XMPP_SASL_URI "}success"
#define XMPP_SASL_FAILURE "{" XMPP_SASL_URI "}failure"

#define XMPP_BIND_URI "urn:ietf:params:xml:ns:xmpp-bind"
#define XMPP_BIND "{" XMPP_BIND_URI "}bind"

#define XMPP_SESSION_URI "urn:ietf:params:xml:ns:xmpp-session"
#define XMPP_SESSION "{" XMPP_SESSION_URI "}session"

#define XMPP_SM_URI "urn:xmpp:sm:3"
#define XMPP_SM "{" XMPP_SM_URI "}sm"
#define XMPP_SM_ENABLE "{" XMPP_SM_URI "}enable"
#define XMPP_SM_ENABLED "{" XMPP_SM_URI "}enabled"
#define XMPP_SM_FAILED "{" XMPP_SM_URI "}failed"
#define XMPP_SM_A_LOCALNAME "a"
#define XMPP_SM_A "{" XMPP_SM_URI "}" XMPP_SM_A_LOCALNAME
#define XMPP_SM_R_LOCALNAME "r"
#define XMPP_SM_R "{" XMPP_SM_URI "}" XMPP_SM_R_LOCALNAME


#endif  // JABBERWERX_TEST_STANZA_DEFINES_H
