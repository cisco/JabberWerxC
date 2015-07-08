/**
 * \file
 * JabberWerxC Echo Server
 *
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010 Cisco Systems, Inc.  All Rights Reserved.
 */

/**
 * Note this program does not handle memory allocation errors as it must not
 * ever be used as anything but a demo.
 */
/**
 * A simple xml stanza echo server implemented using libevent and libjabberwerx.
 * Used to prototype trivial libevent sockets and more
 * fully test jwc xml parser and serializer.
 *
 * Based on earlier work by m&m
 *
 * Typical happy path:
 * Client connects
 * Client sends opening start tag (probably <stream:stream>)
 *      echosrv serializes tag to stdout
 *      echosrv echoes start tag to client.
 * Client sends xml
 *      as each tag is parsed
 *          echosrv serializes each tag to stdout
 *          echosrv echoes tag to client
 * Client sends closing start tag (probably </stream:stream>)
 *      echosrv serializes tag to stdout
 *      echosrv echoes tag to client
 * Client disconnects
 *
 */


#include <netdb.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/dns.h>
#include <event2/event.h>
#include <event2/listener.h>
#include <event2/util.h>

#include <jabberwerx/jabberwerx.h>

const char *_ipaddr = "127.0.0.1:31415";

/********************************************************************
 * xstreamlet, xml parses inbound buffer and fires events. provides
 * a send function to write a node to the outpbound buffer.
 ********************************************************************/
#define EVENT_STREAMLET_ROOT_START "streamletrootstart"
#define EVENT_STREAMLET_ROOT_END "streamletrootend"
#define EVENT_STREAMLET_ELEMENT_RECEIVED "streamelementreceived"
#define EVENT_STREAMLET_ELEMENT_SENT "streamelementsent"
#define EVENT_STREAMLET_CONNECTED "streamletconnected"
#define EVENT_STREAMLET_DISCONNECTED "streamletdisconnected"
#define EVENT_STREAMLET_ERROR "streamleterror"

/* array of serializer write functions ordered by parser event type */
#define INIT_WRITER 0
#define CLOSE_WRITER 1
#define OPEN_WRITER 2
#define ELEMENT_WRITER 3
typedef bool (*jw_serializer_writer)(jw_serializer *ser,
                                     jw_dom_node *node,
                                     jw_err *err);
jw_serializer_writer _serial_writers[] = {NULL,
                                          (jw_serializer_writer)jw_serializer_write_end,
                                          (jw_serializer_writer)jw_serializer_write_start,
                                          (jw_serializer_writer)jw_serializer_write};

const char *_stream_bad_xml = "<stream:error xmlns:stream='http://etherx.jabber.org/streams'>\n"
                                  "<not-well-formed xmlns='urn:ietf:params:xml:ns:xmpp-streams'/>\n"
                              "</stream:error>";
jw_dom_node *_bad_xml = NULL;


typedef struct _xstreamlet_int
{
    struct bufferevent  *bev;
    struct event_base   *evbase;
    evutil_socket_t      fd;

    bool                 closing;
    jw_parser            *parser;
    size_t               curr_writer;
    jw_serializer        *serial;
    jw_dom_node          *root;
    jw_event_dispatcher  *dispatch;
    jw_err              *err;
} _xstreamlet, *xstreamlet;

void xs_send(xstreamlet stream, jw_dom_node *element);

static inline bool _hasErr(jw_err *err)
{
    return err->code != JW_ERR_NONE;
}

#define FIRE_EVENT(stream, event, edata) \
    jw_event_trigger(jw_event_dispatcher_get_event((stream)->dispatch, (event)),\
                    edata, NULL, stream, NULL);

xstreamlet xs_create(struct event_base *evbase) {
#define NEW_EVT(ename) \
    jw_event_dispatcher_create_event(result->dispatch, (ename), &evt, NULL)

    xstreamlet result;
    jw_event *evt;

    result = (xstreamlet)malloc(sizeof(_xstreamlet));
    memset(result, 0, sizeof(_xstreamlet));
    result->evbase = evbase;
    result->err = (jw_err *)malloc(sizeof(jw_err));
    memset(result->err, 0, sizeof(jw_err));
    jw_event_dispatcher_create(result, NULL, &result->dispatch, NULL);

    NEW_EVT(EVENT_STREAMLET_CONNECTED);
    NEW_EVT(EVENT_STREAMLET_DISCONNECTED);
    NEW_EVT(EVENT_STREAMLET_ROOT_START);
    NEW_EVT(EVENT_STREAMLET_ROOT_END);
    NEW_EVT(EVENT_STREAMLET_ELEMENT_RECEIVED);
    NEW_EVT(EVENT_STREAMLET_ELEMENT_SENT);
    NEW_EVT(EVENT_STREAMLET_ERROR);
#undef NEW_EVT
    return result;
}
void xs_destroy(xstreamlet stream)
{
    FIRE_EVENT(stream, EVENT_STREAMLET_DISCONNECTED, NULL);
    bufferevent_free(stream->bev);
    stream->bev = NULL;
    if (stream->root)
    {
        jw_dom_context_destroy(jw_dom_get_context(stream->root));
    }
    /* todo unbind events before destroying dispatcher */
    jw_event_dispatcher_destroy(stream->dispatch);
    jw_parser_destroy(stream->parser);
    jw_serializer_destroy(stream->serial);
    free(stream->err);
    free(stream);
}

/**
 * parser will continue to fire this event while there is data in its buffer
 * (multiple nodes within one buffer). Want to ignore any elements after
 * we we receive root end <stream:stream/>. Mid parse error could have
 * happened along some event chain. Use stream->err in both cases and always
 * continue if set.
 */
static void _parser_open_cb(jw_event_data evt, void *arg)
{
    xstreamlet stream = (xstreamlet)arg;
    if (!_hasErr(stream->err) && !stream->closing)
    {
        stream->root = (jw_dom_node*)evt->data;
        FIRE_EVENT(stream, EVENT_STREAMLET_ROOT_START, (jw_dom_node*)evt->data);
    }
}

static void _parser_closed_cb(jw_event_data evt, void *arg)
{
    UNUSED_PARAM(evt);
    xstreamlet stream = arg;
    if (!_hasErr(stream->err) && !stream->closing)
        {
            stream->closing = true; /* disconnect on root end, handled in onwrite*/
            FIRE_EVENT(stream, EVENT_STREAMLET_ROOT_END, NULL);
        }
}

static void _parser_element_cb(jw_event_data evt, void *arg)
{
    UNUSED_PARAM(evt);
    xstreamlet stream = arg;
    if (!_hasErr(stream->err) && !stream->closing)
    {
        FIRE_EVENT(stream, EVENT_STREAMLET_ELEMENT_RECEIVED, (jw_dom_node*)evt->data);
        jw_dom_context_destroy(jw_dom_get_context((jw_dom_node*)evt->data));
    }
}
static void _buffer_events_cb(struct bufferevent *bev, short events, void *arg)
{
    UNUSED_PARAM(bev);
    if (events & (BEV_EVENT_EOF|BEV_EVENT_ERROR))
    {
        xstreamlet stream = (xstreamlet)arg;
        JABBERWERX_ERROR(stream->err, JW_ERR_INVALID_STATE);
        FIRE_EVENT(stream, EVENT_STREAMLET_ERROR, NULL);
        xs_destroy(stream);
    }
}
static void _buffer_read_cb(struct bufferevent *bev, void *arg)
{
    struct evbuffer *input = bufferevent_get_input(bev);
    bool good_parse;
    xstreamlet stream = (xstreamlet)arg;
    if (_hasErr(stream->err) || stream->closing)
    {
        return;
    }
    /* all streams events for the entire input buffer will be fired
    before process returns */
    good_parse = jw_parser_process(stream->parser, input, stream->err)
                  &&  (stream->err->code != JW_ERR_INVALID_ARG);
    /* was there an xml parse error (and we have not received a root close)? */
    if (!stream->closing && !good_parse)
    {
        JABBERWERX_ERROR(stream->err, JW_ERR_INVALID_ARG);
        /* root xml parse error, serializer never "opened" */
        FIRE_EVENT(stream, EVENT_STREAMLET_ERROR, NULL);
        if (stream->root)
        {   /* Error has been dealt with, just do normal close */
            stream->err->code = JW_ERR_NONE;
            stream->closing = true;
            FIRE_EVENT(stream, EVENT_STREAMLET_ROOT_END, NULL);
        }
        /* _hasErr is now true, write cb will disconnect */
    }
}
static void _buffer_write_cb(struct bufferevent *bev, void *arg)
{
    UNUSED_PARAM(bev);
    xstreamlet    stream = arg;
    if (_hasErr(stream->err) || stream->closing)
    {
        if (_hasErr(stream->err))
        {
            FIRE_EVENT(stream, EVENT_STREAMLET_ERROR, NULL);
        }
        xs_destroy(stream);
    }
}


void xs_open(xstreamlet stream, evutil_socket_t fd)
{
    stream->bev = bufferevent_socket_new(stream->evbase,
                                         fd,
                                         BEV_OPT_CLOSE_ON_FREE);
     /* create as a stream parser */
    jw_parser_create(true, &stream->parser, NULL);
    jw_event_bind(jw_parser_event(stream->parser, JW_PARSER_EVENT_OPEN),
                  _parser_open_cb,
                  stream,
                  NULL);
    jw_event_bind(jw_parser_event(stream->parser, JW_PARSER_EVENT_CLOSED),
                  _parser_closed_cb,
                  stream,
                  NULL);
    jw_event_bind(jw_parser_event(stream->parser, JW_PARSER_EVENT_ELEMENT),
                  _parser_element_cb,
                  stream,
                  NULL);
    
    jw_serializer_create(bufferevent_get_output(stream->bev), &stream->serial, NULL);
    bufferevent_setcb(stream->bev,
                      _buffer_read_cb,
                      _buffer_write_cb,
                      _buffer_events_cb,
                      stream);
    bufferevent_enable(stream->bev, EV_READ | EV_WRITE);
    stream->fd = bufferevent_getfd(stream->bev);
    FIRE_EVENT(stream, EVENT_STREAMLET_CONNECTED, NULL);
}
/* write the given string directly to the output buffer sans eventing
  needed this to echo back the close
*/
void xs_send_str(xstreamlet stream, const char *str)
{
    if (stream->bev)
    {
        struct evbuffer *output = bufferevent_get_output(stream->bev);
        evbuffer_add(output, str, strlen(str));
        evbuffer_add(output, "\n", 1);
    }
}
void xs_send(xstreamlet stream, jw_dom_node *element)
{

    if (stream->bev)
    {
        struct evbuffer *output = bufferevent_get_output(stream->bev);
        if (stream->curr_writer == INIT_WRITER)
        {
            stream->curr_writer = OPEN_WRITER;
        } else if (stream->closing)
        {
            stream->curr_writer = CLOSE_WRITER;
        }

        _serial_writers[stream->curr_writer](stream->serial, element, stream->err);
        evbuffer_add(output, "\n", 1);

        if (stream->curr_writer == OPEN_WRITER)
        {
            stream->curr_writer = ELEMENT_WRITER;
        } else if (stream->curr_writer == CLOSE_WRITER)
        {
            stream->curr_writer = INIT_WRITER;
        }
        FIRE_EVENT(stream, EVENT_STREAMLET_ELEMENT_SENT, element);
    }
}

/**
 * echosrv uses four different event handlers to
 * demonstrate binding to one callback multiple events
 * as well as a single event.
 *
 * "echo" and logging are handled within these callbacks.
 */
static void _conn_events_cb(jw_event_data evt, void *arg)
{
    UNUSED_PARAM(arg);
    xstreamlet stream = evt->source;
    fprintf(stdout, "[SOCKET:%d] ", stream->fd);
    if (strcmp(evt->name, EVENT_STREAMLET_CONNECTED) == 0)
    {
        fprintf(stdout, "Connected\n");
    }
    else
    {
        fprintf(stdout, "Disconnected\n");
    }
}
static void _element_events_cb(jw_event_data evt, void *arg)
{
    UNUSED_PARAM(arg);
    xstreamlet stream = evt->source;
    jw_dom_node *edata = evt->data;
    char *dstr;
    size_t len;
    jw_serialize_xml(edata, &dstr, &len, NULL);
    fprintf(stdout, "[SOCKET:%d] ", stream->fd);

    if (strcmp(evt->name, EVENT_STREAMLET_ELEMENT_RECEIVED) == 0)
    {
        fprintf(stdout, "Rcvd: %s\n", dstr);
        xs_send(stream, edata);
    }
    else
    {
        fprintf(stdout, "Sent: %s\n", dstr);
    }
    jw_data_free(dstr);
}
static void _root_events_cb(jw_event_data evt, void *arg)
{
    UNUSED_PARAM(arg);
    xstreamlet stream = evt->source;

    fprintf(stdout, "[SOCKET:%d] ", stream->fd);
    if (strcmp(evt->name, EVENT_STREAMLET_ROOT_START) == 0)
    {
        char *dstr;
        const char *to, *from;
        size_t len;
        jw_dom_ctx  *ctx;
        jw_dom_node *edata, *features;

        edata = (jw_dom_node*)evt->data;
        ctx = jw_dom_get_context(edata);

        jw_serialize_xml(edata, &dstr, &len, NULL);
        fprintf(stdout, "Start root: %s\n", dstr);
        jw_data_free(dstr);

        from = jw_dom_get_attribute(edata, "{}to");
        to = jw_dom_get_attribute(edata, "{}from");
        
        jw_dom_set_attribute(edata, "{}from", from, NULL);
        jw_dom_set_attribute(edata, "{}to", to, NULL);
        
        jw_dom_set_attribute(edata, "{}id", "somerandomid", NULL);
        
        xs_send(stream, edata);
        jw_dom_element_create(ctx,
                              "{http://etherx.jabber.org/streams}features",
                              &features,
                              NULL);
        jw_dom_add_child(edata, features, NULL);
        xs_send(stream, features);
    }
    else
    {
        fprintf(stdout, "End root: %s\n", jw_dom_get_ename(stream->root));
        xs_send(stream, stream->root);
    }
}
static void _error_event_cb(jw_event_data evt, void *arg)
{
    UNUSED_PARAM(arg);
    xstreamlet stream = evt->source;
    fprintf(stdout, "[SOCKET:%d] Error: ", stream->fd);
    if (stream->err->code == JW_ERR_INVALID_ARG)
    {
        /* xml parse error echo error stanza */
        fprintf(stdout, "Invalid XML\n");
        xs_send(stream, _bad_xml);
    }
    else
    {
        fprintf(stdout, "%s\n", jw_err_message(stream->err->code));
    }
}

static void _accept_callback(struct evconnlistener *l,
                             evutil_socket_t fd,
                             struct sockaddr *addr,
                             int socklent,
                             void *arg)
{
    UNUSED_PARAM(l);
    UNUSED_PARAM(addr);
    UNUSED_PARAM(socklent);

#define EVT_BIND(ename, cb) \
    jw_event_bind(\
        jw_event_dispatcher_get_event(stream->dispatch, (ename)), \
        (cb), (void *)stream, NULL)
    xstreamlet stream = xs_create((struct event_base *)arg);
    /* attach event listeners */
    EVT_BIND(EVENT_STREAMLET_CONNECTED, _conn_events_cb);
    EVT_BIND(EVENT_STREAMLET_DISCONNECTED, _conn_events_cb);
    EVT_BIND(EVENT_STREAMLET_ROOT_START, _root_events_cb);
    EVT_BIND(EVENT_STREAMLET_ROOT_END, _root_events_cb);
    EVT_BIND(EVENT_STREAMLET_ELEMENT_RECEIVED, _element_events_cb);
    EVT_BIND(EVENT_STREAMLET_ELEMENT_SENT, _element_events_cb);
    EVT_BIND(EVENT_STREAMLET_ERROR, _error_event_cb);
    /* open creates buffer and starts listening */
#undef EVT_BIND
    xs_open(stream, fd);
}

/**
 * Setup a new event base and a connection listener to fire _accept_callback
 * and start listening
 */
int main(int argc, char **argv)
{
    UNUSED_PARAM(argc);
    UNUSED_PARAM(argv);

    struct evconnlistener   *connListener;
    struct sockaddr_storage *addr = NULL;
    /* sizea is an integer to match libevent function signatures */
    int                      sizea;
    int                      retval = 0;
    struct event_base       *evbase;

    fprintf(stdout,
            "\n<< starting echo server using JabberWerxC-%s\n",
            jw_version(true));

    addr = (struct sockaddr_storage *)malloc(sizeof(struct sockaddr_storage));
    memset(addr, 0, sizeof(struct sockaddr_storage));
    sizea = sizeof(struct sockaddr_storage);

    /* trivial (and platform independent) connection for localhost */
    if (evutil_parse_sockaddr_port(_ipaddr,(struct sockaddr *)addr, &sizea) == -1)
    {
        fprintf(stderr, "<< shutting down, could not parse address %s >>\n", _ipaddr);
        free(addr);
        return 1;
    }

    evbase = event_base_new();
    connListener = evconnlistener_new_bind(evbase,
                                           _accept_callback, (void *)evbase,
                                           LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE,
                                           -1,
                                           (struct sockaddr *)addr,
                                           sizea);
    if (!connListener)
    {
        fprintf(stderr, "<< shutting down, could not create socket listener >>\n");
        event_base_free(evbase);
        free(addr);
        return 1;
    }
    jw_parse_xml(_stream_bad_xml, &_bad_xml, NULL);
    fprintf(stdout, "<< listening on %s >>\n", _ipaddr);
    retval = event_base_dispatch(evbase);
    fprintf(stdout, "<< shutting down with exit code %d >>\n", retval);

    evconnlistener_free(connListener);
    event_base_free(evbase);
    free(addr);
    jw_dom_context_destroy(jw_dom_get_context(_bad_xml));
    return retval;
}
