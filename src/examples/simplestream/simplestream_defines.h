/**
 * \file
 * simplestream_defines.h
 *
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2011 Cisco Systems, Inc.  All Rights Reserved.
 */

#ifndef SIMPLESTREAM_DEFINES_H
#define SIMPLESTREAM_DEFINES_H

#ifdef __cplusplus
extern "C"
{
#endif

#define XMPP_CLIENT_URI "jabber:client"

#define XMPP_CLIENT_IQ "{" XMPP_CLIENT_URI "}iq"
#define XMPP_CLIENT_PRESENCE "{" XMPP_CLIENT_URI "}presence"

#define XMPP_SASL_URI "urn:ietf:params:xml:ns:xmpp-sasl"

#define XMPP_SASL_MECHS "{" XMPP_SASL_URI "}mechanisms"
#define XMPP_SASL_AUTH "{" XMPP_SASL_URI "}auth"
#define XMPP_SASL_SUCCESS "{" XMPP_SASL_URI "}success"

#define XMPP_BIND_URI "urn:ietf:params:xml:ns:xmpp-bind"

#define XMPP_BIND "{" XMPP_BIND_URI "}bind"

/* TODO for now we'll be using the jid and password from simplestream
 * the values will be stashed in the config passed to the stream which i believe
 * is ultimately correct, but won't be done till later.
 *
 * right now defining and storing jid/password values here, but this should
 * be updated and moved into stream at some point
 */
#define JW_STREAM_CONFIG_USERJID "userjid"
#define JW_STREAM_CONFIG_USERPW "userpassword"

#ifdef __cplusplus
}
#endif

#endif  /* SIMPLESTREAM_DEFINES_H */
