/**
 * \file
 * \brief
 * Main include file for JabberWerxC.
 *
 * Main include file for JabberWerxC. Including this file includes all the
 * public symbols for JabberWerxC.
 *
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 *
 * \mainpage
 *
 * JabberWerxC is a native C library for developing XMPP software. It
 * provides a basic client interface for sending and receiving stanzas,
 * stream handling (both TCP- and BOSH-type connections), namespace-aware
 * DOM, JID representation, and assorted utilities necessary for XMPP. It
 * relies on <a href='http://libevent.org/'>libevent</a> for socket
 * management in an asynchronous manner.
 *
 * A walkthrough of a beginning application is found in the
 * <a href='../../gettingStartedGuide.html'>Getting Started Guide</a>. More
 * documentation can be found through the <a href='../../index.html'>index</a>.
 */

#ifndef JABBERWERX_JABBERWERX_H
#define JABBERWERX_JABBERWERX_H

#include "crypto/sha1.h"
#include "crypto/tls.h"

#include "util/base64.h"
#include "util/hex.h"
#include "util/htable.h"
#include "util/log.h"
#include "util/mem.h"
#include "util/parser.h"
#include "util/serializer.h"
#include "util/states.h"
#include "util/str.h"
#include "util/workq.h"

#include "basics.h"
#include "client.h"
#include "dom.h"
#include "eventing.h"
#include "jid.h"
#include "sasl_factory.h"
#include "sasl_mech.h"
#include "stream.h"
#include "tracker.h"
#include "types-compat.h"

#endif /* JABBERWERX_JABBERWERX_H */
