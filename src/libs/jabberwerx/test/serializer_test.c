/**
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

#include "fct.h"
#include "test_utils.h"

#include <jabberwerx/dom.h>
#include <jabberwerx/util/parser.h>
#include <jabberwerx/util/serializer.h>
#include <jabberwerx/util/str.h>
#include <jabberwerx/util/mem.h>

#include <string.h>


static struct evbuffer *g_output;
static jw_serializer    *g_serializer;
static jw_dom_ctx       *g_domCtx;

static const char *_output_string(struct evbuffer *out)
{
    char    *str;

    evbuffer_add(out, "", 1);
    str = (char *)evbuffer_pullup(out, -1);

    return str;
}
static void _drain_output(struct evbuffer *out, ssize_t amt)
{
    size_t  len = (amt < 0) ? evbuffer_get_length(out) : (size_t)amt;
    evbuffer_drain(out, len);
}
/**
 * Generates a DOM for the following:
    <presence xmlns='jabber:client'/>
 * NOTE: The namespace declarations are IMPLIED; there is no put_namespace to
 * correspond with each declaration in the above XML
 */
static jw_dom_node *_create_simple_node()
{
    jw_dom_node     *elem;

    jw_dom_element_create(g_domCtx, "{jabber:client}presence", &elem, NULL);

    return elem;
}

/**
 * Generates a DOM for the following:
    <stream:stream  xmlns='jabber:client'
                    xmlns:stream='http://etherx.jabber.org/streams'
                    xml:lang='en'
                    to='capulet.net'
                    version='1.0'/>
 */
static jw_dom_node *_create_streamstream(jw_dom_ctx *ctx)
{
    jw_dom_node     *root;

    jw_dom_element_create(ctx,
                          "{http://etherx.jabber.org/streams}stream",
                          &root,
                          NULL);
    jw_dom_put_namespace(root,
                         "",
                         "jabber:client",
                         NULL);
    jw_dom_put_namespace(root,
                         "stream",
                         "http://etherx.jabber.org/streams",
                         NULL);
    jw_dom_set_attribute(root,
                         "{http://www.w3.org/XML/1998/namespace}lang",
                         "en",
                         NULL);
    jw_dom_set_attribute(root,
                         "{}to",
                         "capulet.net",
                         NULL);
    jw_dom_set_attribute(root,
                         "{}version",
                         "1.0",
                         NULL);

    return root;
}
/**
 * Generates a DOM for the following:
    <message    xmlns='jabber:client'
                xml:lang='en'
                to='romeo@montegue.net'
                type='chat'>
        <body>wherefore art thou, Romeo!</body>
        <active xmlns='http://jabber.org/protocol/chatstates'/>
    </message>
 * NOTE: The namespace declarations are IMPLIED; there is no put_namespace to
 * correspond with each declaration in the above XML
 */
static jw_dom_node *_create_message()
{
    jw_dom_node     *elem, *child;

    jw_dom_element_create(g_domCtx,
                          "{jabber:client}message",
                          &elem,
                          NULL);
    jw_dom_set_attribute(elem,
                         "{http://www.w3.org/XML/1998/namespace}lang",
                         "en",
                         NULL);
    jw_dom_set_attribute(elem,
                         "{}to",
                         "romeo@montegue.net",
                         NULL);
    jw_dom_set_attribute(elem,
                         "{}type",
                         "chat",
                         NULL);

    jw_dom_element_create(g_domCtx,
                          "{jabber:client}body",
                          &child,
                          NULL);
    jw_dom_add_child(elem, child, NULL);

    elem = child;
    jw_dom_text_create(g_domCtx,
                       "wherefore art thou, Romeo!",
                       &child,
                       NULL);
    jw_dom_add_child(elem, child, NULL);

    elem = jw_dom_get_parent(elem);
    jw_dom_element_create(g_domCtx,
                          "{http://jabber.org/protocol/chatstates}active",
                          &child,
                          NULL);
    jw_dom_add_child(elem, child, NULL);

    return elem;
}

/**
 * Generates a DOM for the following (and attaches it to the given msg node):
    <html xmlns='http://jabber.org/protocol/xhtml-im'>
        <body xmlns='http://www.w3.org/1999/xhtml'>
            <p>wherefore art thou, <strong style='color: blue'>Romeo</strong>!</p>
        </body>
    </html>
 * NOTE: The namespace declarations are IMPLIED; there is no put_namespace to
 * correspond with each declaration in the above XML
 */
static jw_dom_node *_create_xhtmlim(jw_dom_node *msg)
{
    jw_dom_ctx  *ctx = jw_dom_get_context(msg);
    jw_dom_node *root, *parent, *child;
    jw_err      err;

    jw_dom_element_create(ctx,
                          "{http://jabber.org/protocol/xhtml-im}html",
                          &parent,
                          &err);
    jw_dom_add_child(msg, parent, &err);
    root = parent;

    jw_dom_element_create(ctx,
                          "{http://www.w3.org/1999/xhtml}body",
                          &child,
                          &err);
    jw_dom_add_child(parent, child, &err);

    parent = child;
    jw_dom_element_create(ctx,
                          "{http://www.w3.org/1999/xhtml}p",
                          &child,
                          &err);
    jw_dom_add_child(parent, child, &err);

    parent = child;
    jw_dom_text_create(ctx,
                       "wherefore art thou, ",
                       &child,
                       &err);
    jw_dom_add_child(parent, child, &err);

    jw_dom_element_create(ctx,
                          "{http://www.w3.org/1999/xhtml}strong",
                          &child,
                          &err);
    jw_dom_set_attribute(child,
                         "{}style",
                         "color: blue",
                         &err);
    jw_dom_add_child(parent, child, &err);

    parent = child;
    jw_dom_text_create(ctx,
                       "Romeo",
                       &child,
                       &err);
    jw_dom_add_child(parent, child, &err);

    parent = jw_dom_get_parent(parent);
    jw_dom_text_create(ctx,
                       "!",
                       &child,
                       &err);
    jw_dom_add_child(parent, child, &err);

    return root;
}
/**
 * Generates a DOM for the following:
    <iq xmlns='jabber:client' id='soap1' to='responder@example.com/soap-server' type='set'>"
        "<env:Envelope xmlns:env='http://www.w3.org/2003/05/soap-envelope'>"
            "<env:Header>"
                "<m:reservation xmlns:m='http://travelcompany.example.org/reservation' env:role='http://www.w3.org/2003/05/soap-envelope/role/next' env:mustUnderstand='true'>"
                    "<m:reference>uuid:093a2da1-q345-739r-ba5d-pqff98fe8j7d</m:reference>"
                    "<m:dateAndTime>2001-11-29T13:20:00.000-05:00</m:dateAndTime>"
                "</m:reservation>"
                <n:passenger xmlns:n='http://travelcompany.example.org/employees' env:role='http://www.w3.org/2003/05/soap-envelope/role/next' env:mustUnderstand='true'>"
                    "<n:name>Ake Jogvan Ovind</n:name>"
                "</n:passenger>"
            "</env:Header>"
            "<env:Body>"
                "<p:itinerary xmlns:p='http://travelcompany.example.org/reservation/travel'>"
                "<p:departure>"
                    "<p:departing>New York</p:departing>"
                    "<p:arriving>Los Angeles</p:arriving>"
                    "<p:departureDate>2001-12-14</p:departureDate>"
                    "<p:departureTime>late afternoon</p:departureTime>"
                    "<p:seatPreference>aisle</p:seatPreference>"
                    "</p:departure>"
                    "<p:return>"
                "<p:departing>Los Angeles</p:departing>"
                    "<p:arriving>New York</p:arriving>"
                    "<p:departureDate>2001-12-20</p:departureDate>"
                    "<p:departureTime>mid-morning</p:departureTime>"
                    "<p:seatPreference/>"
                "</p:return>"
                "</p:itinerary>"
            "<q:lodging xmlns:q='http://travelcompany.example.org/reservation/hotels'>"
                "<q:preference>none</q:preference>"
            "</q:lodging>"
            "</env:Body>"
        "</env:Envelope>"
    "</iq>"
 * NOTE: The namespace declarations are IMPLIED; there is no put_namespace to
 * correspond with each declaration in the above XML
 */
static jw_dom_node *_create_soap_message()
{
    jw_dom_node     *root, *parent, *child, *child1, *child2, *child3, *gchild;

    jw_err      err;

    jw_dom_element_create(g_domCtx, "{jabber:client}iq", &root, NULL);
    jw_dom_set_attribute(root, "{}id", "soap1", NULL);
    jw_dom_set_attribute(root, "{}to", "responder@example.com/soap-server", NULL);
    jw_dom_set_attribute(root, "{}type", "set", NULL);

    jw_dom_element_create(g_domCtx, "{http://www.w3.org/2003/05/soap-envelope}Envelope", &parent, NULL);

    jw_dom_put_namespace(parent, "env", "http://www.w3.org/2003/05/soap-envelope", NULL);
    jw_dom_add_child(root, parent, NULL);

    jw_dom_element_create(g_domCtx, "{http://www.w3.org/2003/05/soap-envelope}Header", &child, NULL);
    jw_dom_add_child(parent, child, NULL);
    parent = child; /*parent = Header */

    jw_dom_element_create(g_domCtx, "{http://travelcompany.example.org/reservation}reservation", &child1, NULL);
    jw_dom_put_namespace(child1, "m", "http://travelcompany.example.org/reservation", NULL);
    jw_dom_set_attribute(child1, "{http://www.w3.org/2003/05/soap-envelope}role", "http://www.w3.org/2003/05/soap-envelope/role/next", NULL);
    jw_dom_set_attribute(child1, "{http://www.w3.org/2003/05/soap-envelope}mustUnderstand", "true", NULL);
    jw_dom_add_child(parent, child1, NULL);
    parent = child1; /*parent = reservation*/
    jw_dom_element_create(g_domCtx, "{http://travelcompany.example.org/reservation}reference", &child, NULL);
    jw_dom_add_child(parent, child, NULL);
    parent = child; /*parent = reference*/
    jw_dom_text_create(g_domCtx, "uuid:093a2da1-q345-739r-ba5d-pqff98fe8j7d", &gchild, &err);
    jw_dom_add_child(parent, gchild, NULL);
    parent = jw_dom_get_parent(parent); /*parent = reservation*/
    jw_dom_element_create(g_domCtx, "{http://travelcompany.example.org/reservation}dateAndTime", &child3, NULL);
    jw_dom_add_child(parent, child3, NULL);
    parent = child3; /*parent = dateAndTime */
    jw_dom_text_create(g_domCtx, "2001-11-29T13:20:00.000-05:00", &gchild, &err);
    jw_dom_add_child(parent, gchild, NULL);
    parent = jw_dom_get_parent(parent); /*parent = reservation*/
    parent = jw_dom_get_parent(parent);/*parent = Header*/

    jw_dom_element_create(g_domCtx, "{http://travelcompany.example.org/employees}passenger", &child1, NULL);
    jw_dom_put_namespace(child1, "n", "http://travelcompany.example.org/employees", NULL);
    jw_dom_set_attribute(child1, "{http://www.w3.org/2003/05/soap-envelope}role", "http://www.w3.org/2003/05/soap-envelope/role/next", NULL);
    jw_dom_set_attribute(child1, "{http://www.w3.org/2003/05/soap-envelope}mustUnderstand", "true", NULL);
    jw_dom_add_child(parent, child1, NULL);
    parent = child1; /*parent = passenger*/
    jw_dom_element_create(g_domCtx, "{http://travelcompany.example.org/employees}name", &child2, NULL);
    jw_dom_add_child(parent, child2, NULL);
    parent = child2; /*parent = name*/
    jw_dom_text_create(g_domCtx, "Ake Jogvan Ovind", &child, &err);
    jw_dom_add_child(parent, child, NULL);
    parent = jw_dom_get_parent(parent); /*parent = passenger*/
    parent = jw_dom_get_parent(parent);/*parent = Header*/
    parent = jw_dom_get_parent(parent);/*parent = Envelope*/

    jw_dom_element_create(g_domCtx, "{http://www.w3.org/2003/05/soap-envelope}Body", &child1, NULL);
    jw_dom_add_child(parent, child1, NULL);
    parent = child1; /*parent = Body*/
    jw_dom_element_create(g_domCtx, "{http://travelcompany.example.org/reservation/travel}itinerary", &child, NULL);
    jw_dom_put_namespace(child, "p", "http://travelcompany.example.org/reservation/travel", NULL);
    jw_dom_add_child(parent, child, NULL);
    parent = child; /*parent = Itinerary*/
    jw_dom_element_create(g_domCtx, "{http://travelcompany.example.org/reservation/travel}departure", &child, NULL);
    jw_dom_add_child(parent, child, NULL);
    parent = child; /*parent = departure*/
    jw_dom_element_create(g_domCtx, "{http://travelcompany.example.org/reservation/travel}departing", &child, NULL);
    jw_dom_add_child(parent, child, NULL);
    parent = child; /*parent = departing*/
    jw_dom_text_create(g_domCtx, "New York", &child, &err);
    jw_dom_add_child(parent, child, NULL);
    parent = jw_dom_get_parent(parent); /*parent = departure*/
    jw_dom_element_create(g_domCtx, "{http://travelcompany.example.org/reservation/travel}arriving", &child, NULL);
    jw_dom_add_child(parent, child, NULL);
    parent = child; /*parent = arriving*/
    jw_dom_text_create(g_domCtx, "Los Angeles", &child, &err);
    jw_dom_add_child(parent, child, NULL);
    parent = jw_dom_get_parent(parent); /*parent = departure*/
    jw_dom_element_create(g_domCtx, "{http://travelcompany.example.org/reservation/travel}departureDate", &child, NULL);
    jw_dom_add_child(parent, child, NULL);
    parent = child; /*parent = departureDate*/
    jw_dom_text_create(g_domCtx, "2001-12-14", &child, &err);
    jw_dom_add_child(parent, child, NULL);
    parent = jw_dom_get_parent(parent); /*parent = departure*/
    jw_dom_element_create(g_domCtx, "{http://travelcompany.example.org/reservation/travel}departureTime", &child, NULL);
    jw_dom_add_child(parent, child, NULL);
    parent = child; /*parent = departureTime*/
    jw_dom_text_create(g_domCtx, "late afternoon", &child, &err);
    jw_dom_add_child(parent, child, NULL);
    parent = jw_dom_get_parent(parent); /*parent = departure*/
    jw_dom_element_create(g_domCtx, "{http://travelcompany.example.org/reservation/travel}seatPreference", &child, NULL);
    jw_dom_add_child(parent, child, NULL);
    parent = child; /*parent = seatPreference*/
    jw_dom_text_create(g_domCtx, "aisle", &child, &err);
    jw_dom_add_child(parent, child, NULL);
    parent = jw_dom_get_parent(parent); /*parent = departure*/
    parent = jw_dom_get_parent(parent); /*parent = Itinerary*/

    jw_dom_element_create(g_domCtx, "{http://travelcompany.example.org/reservation/travel}return", &child, NULL);
    jw_dom_add_child(parent, child, NULL);
    parent = child; /*parent = return*/
    jw_dom_element_create(g_domCtx, "{http://travelcompany.example.org/reservation/travel}departing", &child, NULL);
    jw_dom_add_child(parent, child, NULL);
    parent = child; /*parent = departing*/
    jw_dom_text_create(g_domCtx, "Los Angeles", &child, &err);
    jw_dom_add_child(parent, child, NULL);
    parent = jw_dom_get_parent(parent); /*parent = return*/
    jw_dom_element_create(g_domCtx, "{http://travelcompany.example.org/reservation/travel}arriving", &child, NULL);
    jw_dom_add_child(parent, child, NULL);
    parent = child; /*parent = arriving*/
    jw_dom_text_create(g_domCtx, "New York", &child, &err);
    jw_dom_add_child(parent, child, NULL);
    parent = jw_dom_get_parent(parent); /*parent = return*/
    jw_dom_element_create(g_domCtx, "{http://travelcompany.example.org/reservation/travel}departureDate", &child, NULL);
    jw_dom_add_child(parent, child, NULL);
    parent = child; /*parent = departuredate*/
    jw_dom_text_create(g_domCtx, "2001-12-20", &child, &err);
    jw_dom_add_child(parent, child, NULL);
    parent = jw_dom_get_parent(parent); /*parent = return*/
    jw_dom_element_create(g_domCtx, "{http://travelcompany.example.org/reservation/travel}departureTime", &child, NULL);
    jw_dom_add_child(parent, child, NULL);
    parent = child; /*parent = departureTime*/
    jw_dom_text_create(g_domCtx, "mid-morning", &child, &err);
    jw_dom_add_child(parent, child, NULL);
    parent = jw_dom_get_parent(parent); /*parent = return*/
    jw_dom_element_create(g_domCtx, "{http://travelcompany.example.org/reservation/travel}seatPreference", &child, NULL);
    jw_dom_add_child(parent, child, NULL);
    parent = jw_dom_get_parent(parent); /*parent = Itinerary*/
    parent = jw_dom_get_parent(parent); /*parent = Body*/

    jw_dom_element_create(g_domCtx, "{http://travelcompany.example.org/reservation/hotels}lodging", &child, NULL);
    jw_dom_put_namespace(child, "q", "http://travelcompany.example.org/reservation/hotels", NULL);
    jw_dom_add_child(parent, child, NULL);
    parent = child; /*parent = Lodging*/
    jw_dom_element_create(g_domCtx, "{http://travelcompany.example.org/reservation/hotels}preference", &child, NULL);
    jw_dom_add_child(parent, child, NULL);
    parent = child;/*parent = preference*/
    jw_dom_text_create(g_domCtx, "none", &child, &err);
    jw_dom_add_child(parent, child, NULL);
    parent = jw_dom_get_parent(parent); /*parent = lodging*/
    parent = jw_dom_get_parent(parent); /*parent = Body*/
    parent = jw_dom_get_parent(parent); /*parent = Envelope*/
    parent = jw_dom_get_parent(parent); /*parent = iq*/
    return parent;
}

/**
 * Generates a DOM (IJEP-069 example 2) for the following:
 *
 * NOTE: The namespace declarations are IMPLIED; there is no put_namespace to
 * correspond with each declaration in the above XML.
 *
 * inner xmpp child (presence) have jabber:client ns explicitly via put_namespace
 *
 *     <message xmlns='jabber:client' to='userB@example.com/res1'
 *              from='userA@example.com' id='foo123' type='headline'>
 *           <event xmlns='http://jabber.org/protocol/pubsub#event'>
 *              <items node='http://webex.com/connect/temp-presence'>
 *                  <item id='userA@example.com/res1'>"
 *                      <presence xmlns='jabber:client' from='userA@example.com/res1'
 *                                id='1232658255.175991-19' xml:lang='en-US'>
 *                          <c xmlns='http://jabber.org/protocol/caps'
 *                             node='http://jabber.com/jload/3.0.0'
 *                             hash='sha-1' ver='fszhbwwYic8zDjZrhv86HPJGol0='/>
 *                          <x xmlns='jabber:x:delay' stamp='20090122T21:04:14'"
 *                             from='userA@example.com/res1'/>
 *                      </presence>
 *                  </item>
 *                  <item id='userA@example.com/res2'>
 *                      <presence xmlns='jabber:client' from='userA@example.com/res2'
 *                                id='1232658255.175991-20' xml:lang='en-US'>
 *                          <c xmlns='http://jabber.org/protocol/caps'
 *                             node='http://jabber.com/jload/3.0.0'
 *                             hash='sha-1' ver='fszhbwwYic8zDjZrhv86HPJGol0='/>
 *                          <x xmlns='jabber:x:delay' stamp='20090122T21:05:14'
 *                             from='userA@example.com/res2'/>
 *                   </presence>
 *               </item>
 *           </items>
 *       </event>
 *   </message>
 */
static jw_dom_node *_create_temp_sub()
{
    jw_dom_node *parent, *child, *result, *items;
    jw_dom_ctx *ctx;

    jw_dom_context_create(&ctx, NULL);
    jw_dom_element_create(ctx, "{jabber:client}message", &result, NULL);
    jw_dom_set_attribute(result, "{http://www.w3.org/XML/1998/namespace}lang", "en", NULL);
    jw_dom_set_attribute(result, "{}to", "userB@example.com/res1",NULL);
    jw_dom_set_attribute(result, "{}from", "userA@example.com", NULL);
    jw_dom_set_attribute(result, "{}id", "foo123", NULL);
    jw_dom_set_attribute(result, "{}type", "headline", NULL);

    jw_dom_element_create(ctx, "{http://jabber.org/protocol/pubsub#event}event", &child, NULL);
    jw_dom_add_child(result, child, NULL);
    jw_dom_element_create(ctx, "{http://jabber.org/protocol/pubsub#event}items", &items, NULL);
    jw_dom_set_attribute(items, "{}node","http://webex.com/connect/temp-presence", NULL);
    jw_dom_add_child(child, items, NULL);

    jw_dom_element_create(ctx, "{http://jabber.org/protocol/pubsub#event}item", &parent, NULL);
    jw_dom_add_child(items, parent, NULL);
    jw_dom_set_attribute(parent, "{}id", "userA@example.com/res1", NULL);
    jw_dom_element_create(ctx, "{jabber:client}presence", &child, NULL);
    /* adding explicit namespace on xmpp inner child */
    jw_dom_put_namespace(child, "","jabber:client", NULL);
    jw_dom_set_attribute(child, "{}from", "userA@example.com/res1", NULL);
    jw_dom_set_attribute(child, "{}id", "1232658255.175991-19", NULL);
    jw_dom_set_attribute(child, "{http://www.w3.org/XML/1998/namespace}lang", "en-US", NULL);
    jw_dom_add_child(parent, child, NULL);
    parent = child;
    jw_dom_element_create(ctx, "{http://jabber.org/protocol/caps}c", &child, NULL);
    jw_dom_set_attribute(child, "{}node", "http://jabber.com/jload/3.0.0", NULL);
    jw_dom_set_attribute(child, "{}hash", "sha-1", NULL);
    jw_dom_set_attribute(child, "{}ver", "fszhbwwYic8zDjZrhv86HPJGol0=", NULL);
    jw_dom_add_child(parent, child, NULL);
    jw_dom_element_create(ctx, "{jabber:x:delay}x", &child, NULL);
    jw_dom_set_attribute(child, "{}stamp", "20090122T21:04:14", NULL);
    jw_dom_set_attribute(child, "{}from", "userA@example.com/res1", NULL);
    jw_dom_add_child(parent, child, NULL);

    jw_dom_element_create(ctx, "{http://jabber.org/protocol/pubsub#event}item", &parent, NULL);
    jw_dom_add_child(items, parent, NULL);
    jw_dom_set_attribute(parent, "{}id", "userA@example.com/res2", NULL);
    jw_dom_element_create(ctx, "{jabber:client}presence", &child, NULL);
    /* adding explicit namespace on xmpp inner child */
    jw_dom_put_namespace(child, "","jabber:client", NULL);
    jw_dom_set_attribute(child, "{}from", "userA@example.com/res2", NULL);
    jw_dom_set_attribute(child, "{}id", "1232658255.175991-20", NULL);
    jw_dom_set_attribute(child, "{http://www.w3.org/XML/1998/namespace}lang", "en-US", NULL);
    jw_dom_add_child(parent, child, NULL);
    parent = child;
    jw_dom_element_create(ctx, "{http://jabber.org/protocol/caps}c", &child, NULL);
    jw_dom_set_attribute(child, "{}node", "http://jabber.com/jload/3.0.0", NULL);
    jw_dom_set_attribute(child, "{}hash", "sha-1", NULL);
    jw_dom_set_attribute(child, "{}ver", "fszhbwwYic8zDjZrhv86HPJGol0=", NULL);
    jw_dom_add_child(parent, child, NULL);
    jw_dom_element_create(ctx, "{jabber:x:delay}x", &child, NULL);
    jw_dom_set_attribute(child, "{}stamp", "20090122T21:05:14", NULL);
    jw_dom_set_attribute(child, "{}from", "userA@example.com/res2", NULL);
    jw_dom_add_child(parent, child, NULL);

    return result;
}

static bool _serializer_oom_test(jw_dom_node *node, jw_err *err)
{
    jw_dom_ctx    *ctx        = NULL;
    struct evbuffer    *output     = NULL;
    jw_serializer *serializer = NULL;
    jw_dom_node   *root;

    bool ret = false;

    if (!jw_dom_context_create(&ctx, err)
     || !(output = evbuffer_new())
     || !jw_serializer_create(output, &serializer, err)
     || !jw_dom_element_create(ctx, "{http://etherx.jabber.org/streams}stream",
                               &root, err)
     || !jw_dom_put_namespace(root, "", "jabber:client", err)
     || !jw_dom_put_namespace(root, "stream",
                              "http://etherx.jabber.org/streams", err)
     || !jw_dom_set_attribute(root,
                              "{http://www.w3.org/XML/1998/namespace}lang",
                              "en", err)
     || !jw_dom_set_attribute(root, "{}to", "capulet.net", err)
     || !jw_dom_set_attribute(root, "{}version", "1.0", err)
     || !jw_serializer_write_start(serializer, root, err)
     || !jw_serializer_write(serializer, node, err)
     || !jw_serializer_write_end(serializer, err))
    {
        goto _serializer_oom_test_done_label;
    }

    ret = true;

_serializer_oom_test_done_label:
    if (serializer)
    {
        jw_serializer_destroy(serializer);
    }
    if (output)
    {
        evbuffer_free(output);
    }
    if (ctx)
    {
        jw_dom_context_destroy(ctx);
    }
    return ret;
}


static jw_loglevel _initlevel;
FCTMF_FIXTURE_SUITE_BGN(serializer_test)
{
    FCT_SETUP_BGN()
    {
        _initlevel = jw_log_get_level();
        _test_init_counting_memory_funcs();

        g_output = evbuffer_new();
        jw_serializer_create(g_output, &g_serializer, NULL);
        jw_dom_context_create(&g_domCtx, NULL);
    } FCT_SETUP_END()

    FCT_TEARDOWN_BGN()
    {
        jw_dom_context_destroy(g_domCtx);
        jw_serializer_destroy(g_serializer);
        evbuffer_free(g_output);

        fct_chk_eq_int(_test_get_free_count(), _test_get_malloc_count());
        if (_test_get_free_count() != _test_get_malloc_count())
        {
            jw_log(JW_LOG_ERROR,
                   "mem leak detected in %s: %u allocations, %u frees",
                   fctkern_ptr__->ns.curr_test_name,
                   _test_get_malloc_count(), _test_get_free_count());
        }
        _test_uninit_counting_memory_funcs();
        jw_log_set_level(_initlevel);
    } FCT_TEARDOWN_END()

    FCT_TEST_BGN(jw_serializer_createdestroy)
    {
        jw_serializer   *ser;
        jw_err          err;
        struct evbuffer *output;

        fct_req(output = evbuffer_new());
        fct_chk(jw_serializer_create(output,
                                     &ser,
                                     &err) == true);
        fct_chk(jw_serializer_get_output(ser) == output);
        fct_chk(jw_serializer_is_open(ser) == false);

        jw_serializer_destroy(ser);
        evbuffer_free(output);
    } FCT_TEST_END()
    FCT_TEST_BGN(jw_serializer_simple_stages)
    {
        jw_dom_node     *root;
        jw_err          err;
        const char      *xmlExp;
        const char      *xmlAct;

        root = _create_simple_node();
        fct_chk(jw_serializer_write_start(g_serializer, root, &err) == true);
        xmlExp = "<presence xmlns='jabber:client'>";
        xmlAct = _output_string(g_output);
        fct_chk_eq_str(xmlExp, xmlAct);
        _drain_output(g_output, -1);

        fct_chk(jw_serializer_write_end(g_serializer, &err) == true);
        xmlExp = "</presence>";
        xmlAct = _output_string(g_output);
        fct_chk_eq_str(xmlExp, xmlAct);
        _drain_output(g_output, -1);
    } FCT_TEST_END()
    /**
     * test invalid state error.
     * Generates the error if trying to open the serializer when it is already open or trying to write to it if it is close.
     */
    FCT_TEST_BGN(jw_serializer_simple_invalid_state)
    {
        jw_dom_node     *root;
        jw_err          err;
        const char      *xmlExp;
        const char      *xmlAct;

        root = _create_simple_node();
        fct_chk(jw_serializer_is_open(g_serializer) == false);
        fct_chk(jw_serializer_write_start(g_serializer, root, &err) == true);
        xmlExp = "<presence xmlns='jabber:client'>";
        xmlAct = _output_string(g_output);
        fct_chk_eq_str(xmlExp, xmlAct);
        _drain_output(g_output, -1);

        fct_chk(jw_serializer_is_open(g_serializer) == true);
        fct_chk(jw_serializer_write_start(g_serializer, root, &err) == false);
        fct_chk_eq_int(err.code, JW_ERR_INVALID_STATE);
        _drain_output(g_output, -1);

        fct_chk(jw_serializer_write_end(g_serializer, &err) == true);
        xmlExp = "</presence>";
        xmlAct = _output_string(g_output);
        fct_chk_eq_str(xmlExp, xmlAct);
        _drain_output(g_output, -1);

        fct_chk(jw_serializer_is_open(g_serializer) == false);
        fct_chk(jw_serializer_write_end(g_serializer, &err) == false);
        fct_chk_eq_int(err.code, JW_ERR_INVALID_STATE);
    } FCT_TEST_END()
    FCT_TEST_BGN(jw_serializer_simple_oneshot)
    {
        jw_dom_node     *root;
        jw_err          err;
        const char      *xmlExp = NULL;
        const char      *xmlAct = NULL;

        root = _create_simple_node();
        fct_chk(jw_serializer_write(g_serializer, root, &err) == true);

        xmlExp = "<presence xmlns='jabber:client'/>";
        xmlAct = _output_string(g_output);
        fct_chk_eq_str(xmlExp, xmlAct);
        _drain_output(g_output, -1);
    } FCT_TEST_END()
    FCT_TEST_BGN(jw_serializer_simple_string)
    {
        jw_dom_node     *root;
        jw_err          err;
        const char      *xmlExp = NULL;
        char            *xmlAct = NULL;
        size_t          len;

        root = _create_simple_node();
        fct_chk(jw_serialize_xml(root, &xmlAct, &len, &err) == true);
        xmlExp = "<presence xmlns='jabber:client'/>";
        fct_chk_eq_str(xmlExp, xmlAct);
        jw_data_free(xmlAct);
        fct_chk_eq_int(len, 33);
        _drain_output(g_output, -1);
    } FCT_TEST_END()
    FCT_TEST_BGN(jw_serializer_null_length)
    {
        jw_dom_node     *root;
        jw_err          err;
        const char      *xmlExp = NULL;
        char            *xmlAct = NULL;

        root = _create_simple_node();
        fct_chk(jw_serialize_xml(root, &xmlAct, NULL, &err) == true);
        xmlExp = "<presence xmlns='jabber:client'/>";
        fct_chk_eq_str(xmlExp, xmlAct);
        fct_chk_eq_int(strlen(xmlAct), 33);
        jw_data_free(xmlAct);
        _drain_output(g_output, -1);
    } FCT_TEST_END()
    FCT_TEST_BGN(jw_serializer_xml_buffer)
    {
        jw_dom_node     *root;
        jw_err          err;
        size_t          len;
        const char      *xmlExp = NULL;
        char            xmlAct[200];
        struct evbuffer *buffer = evbuffer_new();

        root = _create_message();

        xmlExp = "<message xmlns='jabber:client' xml:lang='en' to='romeo@montegue.net' type='chat'>"
                 "<body>wherefore art thou, Romeo!</body>"
                 "<active xmlns='http://jabber.org/protocol/chatstates'/>"
                 "</message>";;
        fct_chk(jw_serialize_xml_buffer(root, buffer, &len, &err) == true);
        fct_chk(evbuffer_copyout(buffer, xmlAct, len) > 0);
        xmlAct[len] = '\0';
        fct_chk_eq_str(xmlExp, xmlAct);
        fct_chk_eq_int(len, 185);
        fct_chk_eq_int(evbuffer_get_length(buffer), 185);

        evbuffer_free(buffer);
        _drain_output(g_output, -1);
    } FCT_TEST_END()
    FCT_TEST_BGN(jw_serializer_xml_buffer_roundtrip)
    {
        jw_dom_node     *root;
        jw_err          err;
        size_t          len;
        const char      *xmlExp = NULL;
        char            xmlAct[40];
        struct evbuffer *inbuff = evbuffer_new();
        struct evbuffer *outbuff = evbuffer_new();

        xmlExp = "<presence xmlns='jabber:client'/>";
        evbuffer_add(inbuff, xmlExp, strlen(xmlExp));
        fct_chk(jw_parse_xml_buffer(inbuff, &root, &err) == true);

        fct_req(jw_serialize_xml_buffer(root, outbuff, &len, &err) == true);
        fct_chk(evbuffer_copyout(outbuff, xmlAct, len) > 0);
        xmlAct[len] = '\0';
        fct_chk_eq_str(xmlExp, xmlAct);
        fct_chk_eq_int(len, 33);
        fct_chk_eq_int(evbuffer_get_length(outbuff), 33);

        evbuffer_free(inbuff);
        evbuffer_free(outbuff);
        _drain_output(g_output, -1);
        jw_dom_context_destroy(jw_dom_get_context(root));
    } FCT_TEST_END()
    FCT_TEST_BGN(jw_serializer_xml_buffer_append)
    {
        jw_dom_node     *root, *node;
        jw_err          err;
        size_t          len, mnt;
        char            *xmlExp = NULL;
        char            xmlAct[235];
        char            xmlApp[40];
        struct evbuffer *buffer = evbuffer_new();

        root = _create_message();

        xmlExp = "<message xmlns='jabber:client' xml:lang='en' to='romeo@montegue.net' type='chat'>"
                 "<body>wherefore art thou, Romeo!</body>"
                 "<active xmlns='http://jabber.org/protocol/chatstates'/>"
                 "</message>";;
        fct_chk(jw_serialize_xml_buffer(root, buffer, &len, &err) == true);
        fct_chk(evbuffer_copyout(buffer, xmlAct, len) > 0);
        xmlAct[len] = '\0';
        fct_chk_eq_str(xmlExp, xmlAct);
        fct_chk_eq_int(len, 185);
        fct_chk_eq_int(evbuffer_get_length(buffer), 185);

        node = _create_simple_node();
        xmlExp = "<presence xmlns='jabber:client'/>";

        fct_chk(jw_serialize_xml_buffer(node, buffer, &mnt, &err) == true);
        fct_chk_eq_int(mnt, 33);
        fct_chk_eq_int(evbuffer_get_length(buffer), 218);

        fct_chk(evbuffer_remove(buffer, xmlAct, len) > 0);
        fct_chk(evbuffer_copyout(buffer, xmlApp, mnt) > 0);
        xmlApp[mnt] = '\0';
        fct_chk_eq_str(xmlExp, xmlApp);
        fct_chk_eq_int(evbuffer_get_length(buffer), 33);

        evbuffer_free(buffer);
        _drain_output(g_output, -1);
    } FCT_TEST_END()
    FCT_TEST_BGN(jw_serializer_stages_noncontiguous)
    {
        jw_dom_ctx      *ctx;
        jw_dom_node     *root, *child;
        const char      *xmlExp;
        const char      *xmlAct;
        jw_err          err;

        fct_req(jw_dom_context_create(&ctx, &err) == true);
        fct_req(jw_dom_element_create(ctx,
                                      "{http://etherx.jabber.org/streams}stream",
                                      &root,
                                      &err) == true);
        fct_req(jw_dom_put_namespace(root,
                                     "",
                                     "jabber:client",
                                     &err) == true);
        fct_req(jw_dom_put_namespace(root,
                                     "stream",
                                     "http://etherx.jabber.org/streams",
                                     &err) == true);
        fct_req(jw_dom_set_attribute(root,
                                     "{http://www.w3.org/XML/1998/namespace}lang",
                                     "en",
                                     &err) == true);
        fct_req(jw_dom_set_attribute(root,
                                     "{}to",
                                     "capulet.net",
                                     &err) == true);
        fct_req(jw_dom_set_attribute(root,
                                     "{}version",
                                     "1.0",
                                     &err) == true);

        fct_chk(jw_serializer_write_start(g_serializer,
                                          root,
                                          &err) == true);
        xmlExp = "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' xml:lang='en' to='capulet.net' version='1.0'>";
        xmlAct = _output_string(g_output);
        fct_chk_eq_str(xmlExp, xmlAct);
        _drain_output(g_output, -1);
        jw_dom_context_destroy(ctx);

        child = _create_simple_node();
        fct_chk(jw_serializer_write(g_serializer, child, &err) == true);
        xmlExp = "<presence/>";
        xmlAct = _output_string(g_output);
        fct_chk_eq_str(xmlExp, xmlAct);
        _drain_output(g_output, -1);

        fct_chk(jw_serializer_write_end(g_serializer, &err) == true);
        xmlExp = "</stream:stream>";
        xmlAct = _output_string(g_output);
        fct_chk_eq_str(xmlExp, xmlAct);
        _drain_output(g_output, -1);
    } FCT_TEST_END()
  /**
     * test invalid argument error for jw_serializer_write() function
     * Generates the error  if this serializer is not open, and node is not a JW_DOM_TYPE_ELEMENT
     */
    FCT_TEST_BGN(jw_serializer_invalid_arg)
    {
        jw_dom_ctx      *ctx;
        jw_dom_node     *root, *child, *gchild;
        const char      *xmlExp;
        const char      *xmlAct;
        jw_err          err;

        fct_req(jw_dom_context_create(&ctx, &err) == true);

        fct_req(jw_dom_element_create(ctx,
                                      "{jabber:client}message",
                                      &root,
                                      &err) == true);

        fct_req(jw_dom_set_attribute(root,
                                     "{}id",
                                     "<message_chat>",
                                     &err) == true);
        fct_req(jw_dom_set_attribute(root,
                                     "{}from",
                                     "romeo@montegue.net",
                                     &err) == true);
        fct_req(jw_dom_set_attribute(root,
                                     "{}to",
                                     "juliet@capulet.net/balcony",
                                     &err) == true);
        fct_req(jw_dom_set_attribute(root,
                                     "{}type",
                                     "chat",
                                     &err) == true);
        fct_req(jw_dom_element_create(ctx,
                                      "{jabber:client}body",
                                      &child,
                                      &err) == true);
        fct_req(jw_dom_text_create(ctx,
                                   "&hello, 'sir!'",
                                   &gchild,
                                   &err) == true);
        fct_chk(jw_dom_add_child(root, child, &err) == true);
        fct_chk(jw_dom_add_child(child, gchild, &err) == true);

        fct_chk(jw_serializer_write(g_serializer, root, &err) == true);

        xmlExp = "<message xmlns='jabber:client' id='&lt;message_chat&gt;' from='romeo@montegue.net' to='juliet@capulet.net/balcony' type='chat'><body>&amp;hello, 'sir!'</body></message>";
        xmlAct = _output_string(g_output);
        fct_chk_eq_str(xmlExp, xmlAct);
        _drain_output(g_output, -1);

        fct_chk(jw_serializer_write(g_serializer, gchild, &err) == false);
        fct_chk_eq_int(err.code, JW_ERR_INVALID_ARG);
        _drain_output(g_output, -1);
        jw_dom_context_destroy(ctx);
    } FCT_TEST_END()
    /**
     * test serializing DOM with attributes/text nodes containing special entities (&lt;,&gt;,&amp;,&apos;,&quot;).
    */
    FCT_TEST_BGN(jw_serializer_stages_entities)
    {
        jw_dom_ctx      *ctx;
        jw_dom_node     *root, *child, *gchild, *gchild1;
        const char      *xmlExp;
        const char      *xmlAct;
        jw_err          err;

        fct_req(jw_dom_context_create(&ctx, &err) == true);
        fct_req(jw_dom_element_create(ctx,
                                      "{http://etherx.jabber.org/streams}stream",
                                      &root,
                                      &err) == true);
        fct_req(jw_dom_put_namespace(root,
                                     "",
                                     "jabber:client",
                                     &err) == true);
        fct_req(jw_dom_put_namespace(root,
                                     "stream",
                                     "http://etherx.jabber.org/streams",
                                     &err) == true);
        fct_req(jw_dom_set_attribute(root,
                                     "{http://www.w3.org/XML/1998/namespace}lang",
                                     "en",
                                     &err) == true);
        fct_req(jw_dom_set_attribute(root,
                                     "{}version",
                                     "1.0",
                                     &err) == true);

        fct_req(jw_dom_element_create(ctx,
                                      "{jabber:client}message",
                                      &child,
                                      &err) == true);

        fct_req(jw_dom_set_attribute(child,
                                     "{}id",
                                     "<message_chat>",
                                     &err) == true);
        fct_req(jw_dom_set_attribute(child,
                                     "{}from",
                                     "romeo@montegue.net",
                                     &err) == true);
        fct_req(jw_dom_set_attribute(child,
                                     "{}to",
                                     "juliet@capulet.net/balcony",
                                     &err) == true);
        fct_req(jw_dom_set_attribute(child,
                                     "{}type",
                                     "chat",
                                     &err) == true);
        fct_req(jw_dom_element_create(ctx,
                                      "{jabber:client}body",
                                      &gchild,
                                      &err) == true);
        fct_req(jw_dom_text_create(ctx,
                                   "'&<hello>&'",
                                   &gchild1,
                                   &err) == true);
        fct_chk(jw_dom_add_child(root, child, &err) == true);
        fct_chk(jw_dom_add_child(child, gchild, &err) == true);
        fct_chk(jw_dom_add_child(gchild, gchild1, &err) == true);
        fct_chk(jw_serializer_write_start(g_serializer, root, &err) == true);
        xmlExp = "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' xml:lang='en' version='1.0'>";
        xmlAct = _output_string(g_output);
        fct_chk_eq_str(xmlExp, xmlAct);
        _drain_output(g_output, -1);

        fct_chk(jw_serializer_write(g_serializer, child, &err) == true);
        xmlExp = "<message id='&lt;message_chat&gt;' from='romeo@montegue.net' to='juliet@capulet.net/balcony' type='chat'><body>'&amp;&lt;hello&gt;&amp;'</body></message>";
        xmlAct = _output_string(g_output);
        fct_chk_eq_str(xmlExp, xmlAct);
        _drain_output(g_output, -1);
        jw_dom_context_destroy(ctx);

        fct_chk(jw_serializer_write_end(g_serializer, &err) == true);
        xmlExp = "</stream:stream>";
        xmlAct = _output_string(g_output);
        fct_chk_eq_str(xmlExp, xmlAct);
        _drain_output(g_output, -1);
    } FCT_TEST_END()
    /**
     * Serialize the attribute "{http://www.w3.org/XML/1998/namespace}lang" into "xml:lang='value'"(in steps)
    */
    FCT_TEST_BGN(jw_serializer_xmllang_steps)
    {
        jw_dom_ctx      *ctx;
        jw_dom_node     *root, *child;
        const char      *xmlExp;
        const char      *xmlAct;
        jw_err          err;

        fct_req(jw_dom_context_create(&ctx, &err) == true);

        root = _create_streamstream(ctx);
        fct_chk(jw_serializer_write_start(g_serializer,
                                          root,
                                          &err) == true);
        xmlExp = "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' xml:lang='en' to='capulet.net' version='1.0'>";
        xmlAct = _output_string(g_output);
        fct_chk_eq_str(xmlExp, xmlAct);
        _drain_output(g_output, -1);
        jw_dom_context_destroy(ctx);

        child = _create_simple_node();
        fct_req(jw_dom_set_attribute(child,
                                     "{http://www.w3.org/XML/1998/namespace}lang",
                                     "en",
                                     &err) == true);
        fct_chk(jw_serializer_write(g_serializer, child, &err) == true);
        xmlExp = "<presence xml:lang='en'/>";
        xmlAct = _output_string(g_output);
        fct_chk_eq_str(xmlExp, xmlAct);
        _drain_output(g_output, -1);

        fct_chk(jw_serializer_write_end(g_serializer, &err) == true);
        xmlExp = "</stream:stream>";
        xmlAct = _output_string(g_output);
        fct_chk_eq_str(xmlExp, xmlAct);
        _drain_output(g_output, -1);
    } FCT_TEST_END()
    /**
     * Serialize the attribute "{http://www.w3.org/XML/1998/namespace}lang" into "xml:lang='value'"(one-shot)
    */
    FCT_TEST_BGN(jw_serializer_xmllang_oneshot)
    {
        jw_dom_node     *root;
        const char      *xmlExp;
        const char      *xmlAct;
        jw_err          err;

        root = _create_simple_node();
        fct_req(jw_dom_set_attribute(root,
                                     "{http://www.w3.org/XML/1998/namespace}lang",
                                     "en",
                                     &err) == true);
        fct_chk(jw_serializer_write(g_serializer, root, &err) == true);
        xmlExp = "<presence xmlns='jabber:client' xml:lang='en'/>";
        xmlAct = _output_string(g_output);
        fct_chk_eq_str(xmlExp, xmlAct);
        _drain_output(g_output, -1);
    } FCT_TEST_END()
    /**
     * Tests serializing an element with child elements in different namespaces, without requiring those namespaces to be declared(in steps)
    */
    FCT_TEST_BGN(jw_serializer_extchild_steps)
    {
        jw_dom_ctx      *ctx;
        jw_dom_node     *root, *child;
        const char      *xmlExp;
        const char      *xmlAct;
        jw_err          err;

        fct_req(jw_dom_context_create(&ctx, &err) == true);

        root = _create_streamstream(ctx);
        fct_chk(jw_serializer_write_start(g_serializer,
                                          root,
                                          &err) == true);
        xmlExp = "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' xml:lang='en' to='capulet.net' version='1.0'>";
        xmlAct = _output_string(g_output);
        fct_chk_eq_str(xmlExp, xmlAct);
        _drain_output(g_output, -1);
        jw_dom_context_destroy(ctx);

        child = _create_message();
        fct_chk(jw_serializer_write(g_serializer, child, &err) == true);
        xmlExp = "<message xml:lang='en' to='romeo@montegue.net' type='chat'>"
                 "<body>wherefore art thou, Romeo!</body>"
                 "<active xmlns='http://jabber.org/protocol/chatstates'/>"
                 "</message>";
        xmlAct = _output_string(g_output);
        fct_chk_eq_str(xmlExp, xmlAct);
        _drain_output(g_output, -1);

        fct_chk(jw_serializer_write_end(g_serializer, &err) == true);
        xmlExp = "</stream:stream>";
        xmlAct = _output_string(g_output);
        fct_chk_eq_str(xmlExp, xmlAct);
        _drain_output(g_output, -1);
    } FCT_TEST_END()
    /**
     * Tests serializing an element with child elements in different namespaces, without requiring those namespaces to be declared(in one-shot)
    */
    FCT_TEST_BGN(jw_serializer_extchild_oneshot)
    {
        jw_dom_node     *root;
        const char      *xmlExp;
        const char      *xmlAct;
        jw_err          err;

        root = _create_message();
        fct_req(jw_dom_set_attribute(root,
                                     "{http://www.w3.org/XML/1998/namespace}lang",
                                     "en",
                                     &err) == true);
        fct_chk(jw_serializer_write(g_serializer, root, &err) == true);
        xmlExp = "<message xmlns='jabber:client' xml:lang='en' to='romeo@montegue.net' type='chat'>"
                 "<body>wherefore art thou, Romeo!</body>"
                 "<active xmlns='http://jabber.org/protocol/chatstates'/>"
                 "</message>";
        xmlAct = _output_string(g_output);
        fct_chk_eq_str(xmlExp, xmlAct);
        _drain_output(g_output, -1);
    } FCT_TEST_END()
    /**
     * Tests serializing a complex element with child elements in different namespaces, without requiring those namespaces to be declared(in steps)
    */
    FCT_TEST_BGN(jw_serializer_extchild2_steps)
    {
        jw_dom_ctx      *ctx;
        jw_dom_node     *root, *child;
        const char      *xmlExp;
        const char      *xmlAct;
        jw_err          err;

        fct_req(jw_dom_context_create(&ctx, &err) == true);

        root = _create_streamstream(ctx);
        fct_chk(jw_serializer_write_start(g_serializer,
                                          root,
                                          &err) == true);
        xmlExp = "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' xml:lang='en' to='capulet.net' version='1.0'>";
        xmlAct = _output_string(g_output);
        fct_chk_eq_str(xmlExp, xmlAct);
        _drain_output(g_output, -1);
        jw_dom_context_destroy(ctx);

        child = _create_message();
        _create_xhtmlim(child);
        fct_chk(jw_serializer_write(g_serializer, child, &err) == true);
        xmlExp = "<message xml:lang='en' to='romeo@montegue.net' type='chat'>"
                 "<body>wherefore art thou, Romeo!</body>"
                 "<active xmlns='http://jabber.org/protocol/chatstates'/>"
                 "<html xmlns='http://jabber.org/protocol/xhtml-im'>"
                 "<body xmlns='http://www.w3.org/1999/xhtml'>"
                 "<p>wherefore art thou, <strong style='color: blue'>Romeo</strong>!</p>"
                 "</body>"
                 "</html>"
                 "</message>";
        xmlAct = _output_string(g_output);
        fct_chk_eq_str(xmlExp, xmlAct);
        _drain_output(g_output, -1);

        fct_chk(jw_serializer_write_end(g_serializer, &err) == true);
        xmlExp = "</stream:stream>";
        xmlAct = _output_string(g_output);
        fct_chk_eq_str(xmlExp, xmlAct);
        _drain_output(g_output, -1);
    } FCT_TEST_END()
    /**
     * Tests serializing a complex element with child elements in different namespaces, without requiring those namespaces to be declared(in one-shot)
    */
    FCT_TEST_BGN(jw_serializer_extchild2_oneshot)
    {
        jw_dom_node     *root;
        const char      *xmlExp;
        const char      *xmlAct;
        jw_err          err;

        root = _create_message();
        _create_xhtmlim(root);
        fct_req(jw_dom_set_attribute(root,
                                     "{http://www.w3.org/XML/1998/namespace}lang",
                                     "en",
                                     &err) == true);
        fct_chk(jw_serializer_write(g_serializer, root, &err) == true);
        xmlExp = "<message xmlns='jabber:client' xml:lang='en' to='romeo@montegue.net' type='chat'>"
                 "<body>wherefore art thou, Romeo!</body>"
                 "<active xmlns='http://jabber.org/protocol/chatstates'/>"
                 "<html xmlns='http://jabber.org/protocol/xhtml-im'>"
                 "<body xmlns='http://www.w3.org/1999/xhtml'>"
                 "<p>wherefore art thou, <strong style='color: blue'>Romeo</strong>!</p>"
                 "</body>"
                 "</html>"
                 "</message>";
        xmlAct = _output_string(g_output);
        fct_chk_eq_str(xmlExp, xmlAct);
        _drain_output(g_output, -1);
    } FCT_TEST_END()

  /**
     * test SOAP message. xep-072 example #3 is created as a dom and then
     * serialized using an open serializer.
     * The soap message is created in the function _create_soap_message()
     */
FCT_TEST_BGN(jw_serializer_soapmsg_oneshot)
    {
        jw_dom_node     *root;
        const char      *xmlExp;
        const char      *xmlAct;
        jw_err          err;

        root = _create_soap_message();

        fct_chk(jw_serializer_write(g_serializer, root, &err) == true);
        xmlExp = "<iq xmlns='jabber:client' id='soap1' to='responder@example.com/soap-server' type='set'>"
        "<env:Envelope xmlns:env='http://www.w3.org/2003/05/soap-envelope'>"
        "<env:Header>"
        "<m:reservation xmlns:m='http://travelcompany.example.org/reservation' env:role='http://www.w3.org/2003/05/soap-envelope/role/next' env:mustUnderstand='true'>"
        "<m:reference>uuid:093a2da1-q345-739r-ba5d-pqff98fe8j7d</m:reference>"
        "<m:dateAndTime>2001-11-29T13:20:00.000-05:00</m:dateAndTime>"
        "</m:reservation>"
        "<n:passenger xmlns:n='http://travelcompany.example.org/employees' env:role='http://www.w3.org/2003/05/soap-envelope/role/next' env:mustUnderstand='true'>"
        "<n:name>Ake Jogvan Ovind</n:name>"
        "</n:passenger>"
        "</env:Header>"
        "<env:Body>"
        "<p:itinerary xmlns:p='http://travelcompany.example.org/reservation/travel'>"
        "<p:departure>"
        "<p:departing>New York</p:departing>"
        "<p:arriving>Los Angeles</p:arriving>"
        "<p:departureDate>2001-12-14</p:departureDate>"
        "<p:departureTime>late afternoon</p:departureTime>"
        "<p:seatPreference>aisle</p:seatPreference>"
        "</p:departure>"
        "<p:return>"
        "<p:departing>Los Angeles</p:departing>"
        "<p:arriving>New York</p:arriving>"
        "<p:departureDate>2001-12-20</p:departureDate>"
        "<p:departureTime>mid-morning</p:departureTime>"
        "<p:seatPreference/>"
        "</p:return>"
        "</p:itinerary>"
        "<q:lodging xmlns:q='http://travelcompany.example.org/reservation/hotels'>"
        "<q:preference>none</q:preference>"
        "</q:lodging>"
        "</env:Body>"
        "</env:Envelope>"
        "</iq>";
        xmlAct = _output_string(g_output);
        fct_chk_eq_str(xmlExp, xmlAct);
        _drain_output(g_output, -1);
    } FCT_TEST_END()

    /**
     * test temp_sub packet. IJEP-069 example #2 is created as a dom and then
     * serialized using an open serializer.
     *
     * Test an inner child w/ parent's ns but under another ns, esp xmpp
     * temp sub's presence payload is ideal (see protocol)
     *  <message xmlns='jabber:client'>
     *      <x xmlns='http://jabber.org/protocol/pubsub#x>
     *          <presence xmlns="jabber:client"/>
     *      </x>
     *  </message>
     *  note that in this test message has an implied jabber:client.
     */
    FCT_TEST_BGN(jw_serializer_temp_sub_steps)
    {
        jw_dom_ctx      *ctx;
        jw_dom_node     *root;
        const char      *xmlExp;
        const char      *xmlAct;
        jw_err          err;

        jw_dom_context_create(&ctx, NULL);
        root = _create_streamstream(ctx);
        fct_chk(jw_serializer_write_start(g_serializer,
                                          root,
                                          &err) == true);
        xmlExp = "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' xml:lang='en' to='capulet.net' version='1.0'>";
        xmlAct = _output_string(g_output);
        fct_chk_eq_str(xmlExp, xmlAct);
        _drain_output(g_output, -1);
        jw_dom_context_destroy(ctx);

        root = _create_temp_sub();
        fct_chk(jw_serializer_write(g_serializer, root, &err) == true);
        xmlAct = _output_string(g_output);
        xmlExp ="<message xml:lang='en' to='userB@example.com/res1' from='userA@example.com' id='foo123' type='headline'>"
                "<event xmlns='http://jabber.org/protocol/pubsub#event'><items node='http://webex.com/connect/temp-presence'>"
                "<item id='userA@example.com/res1'>"
                "<presence xmlns='jabber:client' from='userA@example.com/res1' id='1232658255.175991-19' xml:lang='en-US'>"
                "<c xmlns='http://jabber.org/protocol/caps' node='http://jabber.com/jload/3.0.0' hash='sha-1' ver='fszhbwwYic8zDjZrhv86HPJGol0='/>"
                "<x xmlns='jabber:x:delay' stamp='20090122T21:04:14' from='userA@example.com/res1'/>"
                "</presence></item><item id='userA@example.com/res2'>"
                "<presence xmlns='jabber:client' from='userA@example.com/res2' id='1232658255.175991-20' xml:lang='en-US'>"
                "<c xmlns='http://jabber.org/protocol/caps' node='http://jabber.com/jload/3.0.0' hash='sha-1' ver='fszhbwwYic8zDjZrhv86HPJGol0='/>"
                "<x xmlns='jabber:x:delay' stamp='20090122T21:05:14' from='userA@example.com/res2'/>"
                "</presence></item></items></event></message>";
        fct_chk_eq_str(xmlExp, xmlAct);
        _drain_output(g_output, -1);

        fct_chk(jw_serializer_write_end(g_serializer, &err) == true);
        xmlExp = "</stream:stream>";
        xmlAct = _output_string(g_output);
        fct_chk_eq_str(xmlExp, xmlAct);

        _drain_output(g_output, -1);
        jw_dom_context_destroy(jw_dom_get_context(root));
    } FCT_TEST_END()

    /**
     * test temp_sub packet. IJEP-069 example #2 is created as a dom and then
     * serialized using an open serializer.
     *
     * Test an inner child w/ parent's ns but under another ns, esp xmpp
     * temp sub's presence payload is ideal (see protocol)
     *  <message xmlns='jabber:client'>
     *      <x xmlns='http://jabber.org/protocol/pubsub#x>
     *          <presence xmlns="jabber:client"/>
     *      </x>
     *  </message>
     *  note that in this test message must declare jabber:client ns.
     */
    FCT_TEST_BGN(jw_serializer_temp_sub_oneshot)
    {
        jw_dom_node     *root;
        const char      *xmlExp;
        char            *xmlAct = NULL;
        jw_err          err;
        size_t          len;

        xmlExp ="<message xmlns='jabber:client' xml:lang='en' to='userB@example.com/res1' from='userA@example.com' id='foo123' type='headline'>"
                "<event xmlns='http://jabber.org/protocol/pubsub#event'><items node='http://webex.com/connect/temp-presence'>"
                "<item id='userA@example.com/res1'>"
                "<presence xmlns='jabber:client' from='userA@example.com/res1' id='1232658255.175991-19' xml:lang='en-US'>"
                "<c xmlns='http://jabber.org/protocol/caps' node='http://jabber.com/jload/3.0.0' hash='sha-1' ver='fszhbwwYic8zDjZrhv86HPJGol0='/>"
                "<x xmlns='jabber:x:delay' stamp='20090122T21:04:14' from='userA@example.com/res1'/>"
                "</presence></item><item id='userA@example.com/res2'>"
                "<presence xmlns='jabber:client' from='userA@example.com/res2' id='1232658255.175991-20' xml:lang='en-US'>"
                "<c xmlns='http://jabber.org/protocol/caps' node='http://jabber.com/jload/3.0.0' hash='sha-1' ver='fszhbwwYic8zDjZrhv86HPJGol0='/>"
                "<x xmlns='jabber:x:delay' stamp='20090122T21:05:14' from='userA@example.com/res2'/>"
                "</presence></item></items></event></message>";

        root = _create_temp_sub();
        fct_chk(jw_serialize_xml(root, &xmlAct, &len, &err) == true);
        fct_chk_eq_str(xmlAct, xmlExp);
        fct_chk_eq_int(len, 998);
        jw_dom_context_destroy(jw_dom_get_context(root));
        jw_data_free(xmlAct);
    } FCT_TEST_END()

    /**
     * test round-trip temp_sub packet. IJEP-069 example #2 is parsed from
     * a string, serialized and compared to the original string
     */
    FCT_TEST_BGN(jw_serializer_temp_sub_round_trip)
    {
        jw_dom_node     *root;
        const char      *xmlExp;
        char            *xmlAct = NULL;
        jw_err          err;
        size_t          len;

        xmlExp ="<message xmlns='jabber:client' xml:lang='en' to='userB@example.com/res1' from='userA@example.com' id='foo123' type='headline'>"
                "<event xmlns='http://jabber.org/protocol/pubsub#event'><items node='http://webex.com/connect/temp-presence'>"
                "<item id='userA@example.com/res1'>"
                "<presence xmlns='jabber:client' from='userA@example.com/res1' id='1232658255.175991-19' xml:lang='en-US'>"
                "<c xmlns='http://jabber.org/protocol/caps' node='http://jabber.com/jload/3.0.0' hash='sha-1' ver='fszhbwwYic8zDjZrhv86HPJGol0='/>"
                "<x xmlns='jabber:x:delay' stamp='20090122T21:04:14' from='userA@example.com/res1'/>"
                "</presence></item><item id='userA@example.com/res2'>"
                "<presence xmlns='jabber:client' from='userA@example.com/res2' id='1232658255.175991-20' xml:lang='en-US'>"
                "<c xmlns='http://jabber.org/protocol/caps' node='http://jabber.com/jload/3.0.0' hash='sha-1' ver='fszhbwwYic8zDjZrhv86HPJGol0='/>"
                "<x xmlns='jabber:x:delay' stamp='20090122T21:05:14' from='userA@example.com/res2'/>"
                "</presence></item></items></event></message>";
        fct_chk(jw_parse_xml(xmlExp, &root, &err) == true);
        fct_chk(jw_serialize_xml(root, &xmlAct, &len, &err) == true);
        fct_chk_eq_str(xmlAct, xmlExp);
        fct_chk_eq_int(len, 998);
        jw_dom_context_destroy(jw_dom_get_context(root));
        jw_data_free(xmlAct);
    } FCT_TEST_END()

    /**
     * test round-trip string containing special entities (&lt;,&gt;,&amp;,&apos;,&quot;).
     * parsed from a string, serialized and compared to the original string
     */
    FCT_TEST_BGN(jw_serializer_spl_entities_round_trip)
    {
        jw_dom_node     *root;
        const char      *xmlExp;
        char            *xmlAct = NULL;
        jw_err          err;
        size_t          len;

        xmlExp ="<message xmlns='jabber:client' id='&lt;message_chat&gt;' from='romeo@montegue.net' to='juliet@capulet.net/balcony' type='chat'><body>&amp;&lt;hello&gt;&amp;</body></message>";
        fct_req(jw_parse_xml(xmlExp, &root, &err) == true);
        fct_chk(jw_serialize_xml(root, &xmlAct, &len, &err) == true);
        fct_chk_eq_str(xmlAct, xmlExp);
        fct_chk_eq_int(len, 173);
        jw_dom_context_destroy(jw_dom_get_context(root));
        jw_data_free(xmlAct);
    } FCT_TEST_END()
    /**
     * test round-trip packet with well-known extensions.
     */
    FCT_TEST_BGN(jw_serializer_ext_child2_round_trip)
    {
        jw_dom_node     *root;
        const char      *xmlExp;
        char            *xmlAct = NULL;
        jw_err          err;
        size_t          len;

        xmlExp ="<message xmlns='jabber:client' xml:lang='en' to='romeo@montegue.net' type='chat'>"
                 "<body>wherefore art thou, Romeo!</body>"
                 "<active xmlns='http://jabber.org/protocol/chatstates'/>"
                 "<html xmlns='http://jabber.org/protocol/xhtml-im'>"
                 "<body xmlns='http://www.w3.org/1999/xhtml'>"
                 "<p>wherefore art thou, <strong style='color: blue'>Romeo</strong>!</p>"
                 "</body>"
                 "</html>"
                 "</message>";
        fct_req(jw_parse_xml(xmlExp, &root, &err) == true);
        fct_chk(jw_serialize_xml(root, &xmlAct, &len, &err) == true);
        fct_chk_eq_str(xmlAct, xmlExp);
        fct_chk_eq_int(len, 362);
        jw_dom_context_destroy(jw_dom_get_context(root));
        jw_data_free(xmlAct);
    } FCT_TEST_END()
    /**
     * test round-trip packet to test ordering of namespace declarations.
     */
    FCT_TEST_BGN(jw_serializer_ns_order_round_trip)
    {
        jw_dom_node     *root;
        const char      *xmlExp;
        char            *xmlAct = NULL;
        jw_err          err;
        size_t          len;

        xmlExp ="<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' xml:lang='en' to='capulet.net' version='1.0'/>";
        fct_req(jw_parse_xml(xmlExp, &root, &err) == true);
        fct_chk(jw_serialize_xml(root, &xmlAct, &len, &err) == true);
        fct_chk_eq_str(xmlAct, xmlExp);
         fct_chk_eq_int(len, 131);
        jw_dom_context_destroy(jw_dom_get_context(root));
        jw_data_free(xmlAct);
    } FCT_TEST_END()
     /**
     * test round-trip packet having quoted attributes and namespace declaration.
     */
    FCT_TEST_BGN(jw_serializer_quoted_attr_round_trip)
    {
        jw_dom_node     *root;
        const char      *xmlExp, *xmlSer;
        char            *xmlAct = NULL;
        jw_err          err;
        size_t          len;

        xmlExp ="<message xmlns='jabber:client' to=\"romeo@montegue.net\">"
                 "<active xmlns=\"http://jabber.org/chatstates\"/>"
                   "</message>";
        fct_req(jw_parse_xml(xmlExp, &root, &err) == true);
        fct_chk(jw_serialize_xml(root, &xmlAct, &len, &err) == true);

        xmlSer ="<message xmlns='jabber:client' to='romeo@montegue.net'>"
                 "<active xmlns='http://jabber.org/chatstates'/>"
                   "</message>";
        fct_chk_eq_str(xmlAct, xmlSer);
        fct_chk_eq_int(len, 111);
        jw_dom_context_destroy(jw_dom_get_context(root));
        jw_data_free(xmlAct);
    } FCT_TEST_END()
    /**
     * test round-trip SOAP message packet. IJEP-072 example #3 is parsed from
     * a string, serialized and compared to the original string
     */
    FCT_TEST_BGN(jw_serializer_soap_round_trip)
    {
        jw_dom_node     *root;
        const char      *xmlExp;
        char            *xmlAct = NULL;
        jw_err          err;
        size_t          len;

        xmlExp ="<iq xmlns='jabber:client' id='soap1' to='responder@example.com/soap-server' type='set'>"
        "<env:Envelope xmlns:env='http://www.w3.org/2003/05/soap-envelope'>"
        "<env:Header>"
        "<m:reservation xmlns:m='http://travelcompany.example.org/reservation' env:role='http://www.w3.org/2003/05/soap-envelope/role/next' env:mustUnderstand='true'>"
        "<m:reference>uuid:093a2da1-q345-739r-ba5d-pqff98fe8j7d</m:reference>"
        "<m:dateAndTime>2001-11-29T13:20:00.000-05:00</m:dateAndTime>"
        "</m:reservation>"
        "<n:passenger xmlns:n='http://travelcompany.example.org/employees' env:role='http://www.w3.org/2003/05/soap-envelope/role/next' env:mustUnderstand='true'>"
        "<n:name>Ake Jogvan Ovind</n:name>"
        "</n:passenger>"
        "</env:Header>"
        "<env:Body>"
        "<p:itinerary xmlns:p='http://travelcompany.example.org/reservation/travel'>"
        "<p:departure>"
        "<p:departing>New York</p:departing>"
        "<p:arriving>Los Angeles</p:arriving>"
        "<p:departureDate>2001-12-14</p:departureDate>"
        "<p:departureTime>late afternoon</p:departureTime>"
        "<p:seatPreference>aisle</p:seatPreference>"
        "</p:departure>"
        "<p:return>"
        "<p:departing>Los Angeles</p:departing>"
        "<p:arriving>New York</p:arriving>"
        "<p:departureDate>2001-12-20</p:departureDate>"
        "<p:departureTime>mid-morning</p:departureTime>"
        "<p:seatPreference/>"
        "</p:return>"
        "</p:itinerary>"
        "<q:lodging xmlns:q='http://travelcompany.example.org/reservation/hotels'>"
        "<q:preference>none</q:preference>"
        "</q:lodging>"
        "</env:Body>"
        "</env:Envelope>"
        "</iq>";
        fct_chk(jw_parse_xml(xmlExp, &root, &err) == true);
        fct_chk(jw_serialize_xml(root, &xmlAct, &len, &err) == true);
        fct_chk_eq_str(xmlAct, xmlExp);
        fct_chk_eq_int(len, 1363);
        jw_dom_context_destroy(jw_dom_get_context(root));
        jw_data_free(xmlAct);
    } FCT_TEST_END()
	/**
	 * Generates a DOM for the following (and attaches it to the given msg node):
	 <foo xmlns='jabber:client' attr1='&lt;&amp;&quot;&apos;&gt;'>
	 &lt;&amp;&quot;&#60;&#62;
	 <bar>bar text</bar>&apos;&gt;01234567890</foo>
	 * NOTE: The namespace declarations are IMPLIED; there is no put_namespace to
	 * correspond with each declaration in the above XML
	 */
    FCT_TEST_BGN(jw_serializer_textnode)
    {
        jw_dom_ctx      *ctx;
        jw_dom_node     *root, *child, *gchild;
        const char      *xmlExp;
        const char      *xmlAct;
        jw_err          err;

		fct_req(jw_dom_context_create(&ctx, &err) == true);
		fct_req(jw_dom_element_create(ctx, "{jabber:client}foo", &root, &err) == true);
		fct_req(jw_dom_put_namespace(root, "", "jabber:client", &err) == true);
		fct_req(jw_dom_text_create(ctx, "<&\"<>", &child, &err) == true);
		fct_req(jw_dom_add_child(root, child, &err) == true);
		fct_req(jw_dom_element_create(ctx, "{jabber:client}bar", &child, &err) == true);
		fct_req(jw_dom_add_child(root, child, &err) == true);
		fct_req(jw_dom_text_create(ctx, "bar text", &gchild, &err) == true);
		fct_req(jw_dom_add_child(child, gchild, &err) == true);
		fct_req(jw_dom_text_create(ctx, "'>01234567890", &child, &err) == true);
		fct_req(jw_dom_add_child(root, child, &err) == true);
		fct_req(jw_dom_set_attribute(root, "{}attr1", "<&\"'>", &err) == true);


        fct_chk(jw_serializer_write(g_serializer, root, &err) == true);
        xmlExp = "<foo xmlns='jabber:client' attr1='&lt;&amp;&quot;&apos;&gt;'>&lt;&amp;\"&lt;&gt;"
		"<bar>bar text</bar>\'&gt;01234567890</foo>";
        xmlAct = _output_string(g_output);
        fct_chk_eq_str(xmlExp, xmlAct);

        jw_dom_context_destroy(ctx);
        _drain_output(g_output, -1);
    } FCT_TEST_END()
	/**
	 * Serializes and parses the following:
	 <foo xmlns='jabber:client' attr1='&lt;&amp;&quot;&apos;&gt;'>
	 &lt;&amp;&quot;&#60;&#62;
	 <bar>bar text</bar>&apos;&gt;01234567890</foo>
	 *
	 */
    FCT_TEST_BGN(jw_serializer_textnode_round_trip)
    {
        jw_dom_node     *root;
        const char      *xmlExp, *xmlSer;
        char            *xmlAct = NULL;
        jw_err          err;
        size_t          len;

        xmlExp ="<foo xmlns='jabber:client' attr1='&lt;&amp;&quot;&apos;&gt;'>"
		"&lt;&amp;&quot;&#60;&#62;<bar>bar text</bar>&apos;&gt;01234567890</foo>";
        fct_req(jw_parse_xml(xmlExp, &root, &err) == true);
        fct_chk(jw_serialize_xml(root, &xmlAct, &len, &err) == true);
        xmlSer ="<foo xmlns='jabber:client' attr1='&lt;&amp;&quot;&apos;&gt;'>"
		"&lt;&amp;\"&lt;&gt;<bar>bar text</bar>\'&gt;01234567890</foo>";
        fct_chk_eq_str(xmlAct, xmlSer);
        fct_chk_eq_int(len, 120);
        jw_dom_context_destroy(jw_dom_get_context(root));
        jw_data_free(xmlAct);
    } FCT_TEST_END()

    /**
	 * Serializes and parses valid utf-8 characters(related to DE699)
	 *
	 */
    FCT_TEST_BGN(jw_serializer_textnode_utf8_round_trip)
    {
        jw_dom_node     *root;
        const char      *xmlExp, *xmlSer;
        char            *xmlAct = NULL;
        jw_err          err;
        size_t          len;

        xmlExp ="<foo xmlns='jabber:client' attr1='υعε4g-用WυsοPس用h&quot;'>"
		"<bar>vZvubعσ€Y@Cn9yا)vي?اοU*.cف2~</bar></foo>";
        fct_req(jw_parse_xml(xmlExp, &root, &err) == true);
        fct_chk(jw_serialize_xml(root, &xmlAct, &len, &err) == true);
        xmlSer ="<foo xmlns='jabber:client' attr1='υعε4g-用WυsοPس用h&quot;'>"
		"<bar>vZvubعσ€Y@Cn9yا)vي?اοU*.cف2~</bar></foo>";
        fct_chk_eq_str(xmlAct, xmlSer);
        fct_chk_eq_int(len, 121);
        jw_dom_context_destroy(jw_dom_get_context(root));
        jw_data_free(xmlAct);
    } FCT_TEST_END()

    FCT_TEST_BGN(jw_serializer_oom)
    {
        //jw_log_set_level(JW_LOG_TRACE);

        jw_err err;

        jw_dom_node *node = _create_soap_message();
        fct_req(node);

        OOM_RECORD_ALLOCS(_serializer_oom_test(node, &err));
        OOM_TEST_INIT();
        OOM_TEST(&err, _serializer_oom_test(node, &err));
        OOM_TEST_INIT();
        OOM_TEST(NULL, _serializer_oom_test(node, NULL));
    } FCT_TEST_END()

    FCT_TEST_BGN(jw_serializer_no_close)
    {
        //jw_log_set_level(JW_LOG_TRACE);

        jw_dom_node *root, *child;

        // let test fixture check for memory leaks
        fct_req(jw_dom_element_create(
            g_domCtx, "{http://etherx.jabber.org/streams}stream", &root, NULL));
        fct_req(jw_dom_put_namespace(root, "", "jabber:client", NULL));
        fct_req(jw_dom_put_namespace(
            root, "stream", "http://etherx.jabber.org/streams", NULL));
        fct_req(jw_dom_set_attribute(
            root, "{http://www.w3.org/XML/1998/namespace}lang", "en", NULL));
         fct_req(jw_dom_set_attribute(root, "{}to", "capulet.net", NULL));
         fct_req(jw_serializer_write_start(g_serializer, root, NULL));
         fct_req(jw_dom_element_create(
            g_domCtx, "{jabber:client}presence", &child, NULL));
         fct_req(jw_serializer_write(g_serializer, child, NULL));
    } FCT_TEST_END()
} FCTMF_FIXTURE_SUITE_END()
