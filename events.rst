..
    Portions created or assigned to Cisco Systems, Inc. are
    Copyright (c) 2011 Cisco Systems, Inc.  All Rights Reserved.
..

.. meta::
   :description: This is a general description of events in |JWC| and a
                 detailed description of each event.
   :copyright: Copyright (c) 2011 Cisco Systems, Inc.  All Rights Reserved.
   :dateModified: 2011-02-02

.. |JWC| replace:: JabberWerxC

|JWC| Events
======================

.. contents:: Table of Contents

Introduction
------------
This is a general explanation of events in |JWC| with code examples.


jw_stream Events
----------------

Keep in mind that jw_dom_context_destroy() will be called on the stanza context
regardless of the value of the handled flag and regardless of whether the stanza
was successfully received or sent out.  If you need to access the stanza or its
context after the event, ensure you first call jw_dom_context_retain() to
increment the context refcount.

======================  =====================   ================================
Name                    Data                    Description
======================  =====================   ================================
streamOpened            <stream:features/>      Triggered when the stream is
                        element, as a           opened. The event data is the
                        jw_dom_node             set of features reported by the
                                                remote endpoint.
streamClosed            <stream:error/>         Triggered when a stream is
                        element, as a           closed. The data is present if
                        jw_dom_node             the stream did not close
                                                gracefully; otherwise the event
                                                data is NULL.

                                                **NOTE** This event may be
                                                triggered before the stream is
                                                opened; e.g. there are network
                                                errors opening the stream.
streamElementsReceived  NULL-terminated array   Triggered when elements are
                        of elements, as         received from the remote
                        jw_dom_node *           endpoint. The event data always
                                                contains at least one element.
streamElementsSent      NULL-terminated array   Triggered when elements are
                        of elements, as         sent to the remote endpoint.
                        jw_dom_node *           The event data always contains
                                                at least one element.
streamDestroyed         NULL                    Triggered just before freeing
                                                the stream object and its state.
                                                jw_stream_get_* methods are safe
                                                to call, but no new events
                                                should be triggered and no
                                                further data should be sent.

======================  =====================   ================================


jw_client Status Events
-----------------------

jw_client defines three events that may occur during a status change:
clientStatusChanged, clientConnected and clientDisconnected.
clientStatusChanged is a general event that fires with every status
change while clientConnected and clientDisconnected are specific
to one status.

clientStatusChanged events are passed a jw_client_status struct whose
members (previous, current, reconnecting and error) should be accessed through
their corresponding jw_client getters. The previous status is the status of
the client prior to the now current status. The reconnecting boolean flag
indicates this status change is occurring during a reconnection attempt.The
error is optional and will only be set as needed when disconnected. For instance
if the event were triggered because of an authentication error, the
previous status would be JW_CLIENT_CONNECTING, the current status
JW_CLIENT_DISCONNECTED and the error set to the auth error encountered.

===================  =================   =======================================
Name                 Data                Description
===================  =================   =======================================
clientStatusChanged  jw_client_status    Triggered when the client changes
                                         connection states.  The previous and
                                         current status are of type
                                         jw_client_statustype and will be one of
                                             JW_CLIENT_DISCONNECTED
                                             JW_CLIENT_CONNECTING
                                             JW_CLIENT_CONNECTED
                                             JW_CLIENT_DISCONNECTING
                                         An error may be set if the disconnect
                                         was not graceful.
                                         A reconnecting flag will be true if
                                         the status change is happening during
                                         a reconnection state.
clientConnected      NULL                Triggered when the client is fully
                                         authenticated and ready to send and
                                         receive XMPP stanzas.
clientDisconnected   jw_dom_node error   Triggered when the client is fully
                                         disconnected.  data will be set if the
                                         disconnect was the result of a stream
                                         or authentication error.  Contains at
                                         least one element.
clientDestroyed      NULL                Triggered just before freeing the
                                         client object and its state.
                                         jw_client_get_* methods are safe to
                                         call, but no new events should be
                                         triggered and no further data should be
                                         sent.
===================  =================   =======================================

jw_client Reconnect Status Event
--------------------------------

jw_client defines the reconnectStatus event to signal a change in reconnection
state. The event is passed a jw_client_reconnect_status struct whose members
(status, countdown, attempts) should be accessed through their corresponding
jw_client getters. The status member may be one of JW_CLIENT_RECONNECT_PENDING,
JW_CLIENT_RECONNECT_STARTING, JW_CLIENT_RECONNECT_CANCELED. The countdown member
is the number of seconds from the end of the last attempt to the start of the
next one. The attempts member is a counter showing how many attempts to
reconnect have been made.

A status of JW_CLIENT_RECONNECT_PENDING indicates a reconnect attempt will occur
at some time in the future. The client's status is JW_CLIENT_DISCONNECTED and
the disconnect occurred because of some network or server error.
JW_CLIENT_RECONNECT_STARTING is used when a pending attempt is started. This
reconnectStatus event is triggered at the same time a clientStatusChanged
JW_CLIENT_CONNECTING event is triggered.
Finally a JW_CLIENT_RECONNECT_CANCELED status indicates a pending reconnect
attempt has been canceled and the client will no longer attempt reconnection.

======================  ==========================   ==============================
Name                    Data                         Description
======================  ==========================   ==============================
reconnectStatusChanged  jw_client_reconnect_status   Triggered when the client's
                                                     reconnection state has changed.
                                                     The status may be one of
                                                       JW_CLIENT_RECONNECT_PENDING
                                                       JW_CLIENT_RECONNECT_STARTING
                                                       JW_CLIENT_RECONNECT_CANCELED
                                                     countdown will be the current
                                                     attempt interval in seconds
                                                     attempts will be the number of
                                                     previous failed attempts.
======================  ==========================   ==============================

jw_client Session Events
------------------------

|JWC| implements XEP-0198, session management, allowing a jw_client object to
pause and resume stream sessions. Two events are provided that allow the library
user to detect when session state changes occur.

**Note** session pausing and resumption are contigent upon whether auto reconnect
is enabled, the disconnect error is recoverable, stream managment and session
resumption are enabled on both the client and server.

**Note** While paused jw_client will not receive packets but the user may
continue to queue outbound packets until resumption or connection failure.

====================  =================  ============================================
Name                  Data               Description
====================  =================  ============================================
clientSessionPaused   jw_dom_node error  Triggered when the client was
                                         unexpectedly disconnected and session
                                         resumption is possible. data will be
                                         the stream error that caused the event.
                                         or authentication error
clientSessionResumed  NULL               XEP-0198 session resumption was
                                         successful.
====================  =================  =============================================


jw_client Stanza Events
-----------------------

jw_client triggers events based on stanza kind (iq, presence or message) and
direction (sent, received). Events are triggered in the expected order:
before[->on[->after]].

If any callback sets the event handled flag to true, processing of that stanza
kind ceases. For instance, if a beforeIqReceived callback set handled to true,
iqReceived and afterIqReceived will not be triggered.

Keep in mind that jw_dom_context_destroy() will be called on the stanza context
regardless of the value of the handled flag and regardless of whether the stanza
was successfully received or sent out.  If you need to access the stanza or its
context after the event, ensure you first call jw_dom_context_retain() to
increment the context refcount.

======================  ==================   =================================
Name                    Data                 Description
======================  ==================   =================================
beforeIqReceived        jw_dom_node stanza   Preprocess an iq stanza.
iqReceived              jw_dom_node stanza   Normal processing of iq stanza
afterIqReceived         jw_dom_node stanza   Postprocessing an iq stanza
beforePresenceReceived  jw_dom_node stanza   Preprocess a presence stanza.
presenceReceived        jw_dom_node stanza   Normal processing presence stanza
afterPresenceReceived   jw_dom_node stanza   Postprocessing presence stanza
beforeMessageReceived   jw_dom_node stanza   Preprocess a message stanza.
messageReceived         jw_dom_node stanza   Normal processing message stanza
afterMessageReceived    jw_dom_node stanza   Postprocessing message stanza

beforeIqSent            jw_dom_node stanza   Triggered before the iq is sent
iqSent                  jw_dom_node stanza   Triggered after the iq is sent
beforePresenceSent      jw_dom_node stanza   Triggered before presence is sent
presenceSent            jw_dom_node stanza   Triggered after presence is sent
beforeMessageSent       jw_dom_node stanza   Triggered before message is sent
messageSent             jw_dom_node stanza   Triggered after message is sent

======================  ==================   =================================
