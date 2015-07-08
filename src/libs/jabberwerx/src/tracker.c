/**
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

#include <jabberwerx/util/htable.h>
#include <jabberwerx/util/log.h>
#include <jabberwerx/util/str.h>
#include <jabberwerx/jid.h>
#include <jabberwerx/tracker.h>

#include <event2/event.h>

#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>

#define STR_RESULT "result"
#define STR_RESULT_LEN sizeof(STR_RESULT)
#define STR_ERROR "error"
#define STR_ERROR_LEN sizeof(STR_ERROR)

#define TRACKER_HTABLE_SIZE 317

typedef struct _jw_tracker_t
{
    jw_htable           *pending;
    uint64_t            last_id;
    struct event_base  *selector;
} jw_tracker_t;

typedef struct _jw_match_t
{
    char *jid;
    char *id;
    char *typ;
} jw_match_t, *jw_match;

typedef struct _jw_action_t
{
    jw_tracker_cb_func   cb;
    void                *arg;
    struct event        *timeout;
    jw_match             match;
    jw_tracker           *tracker;
} jw_action_t, *jw_action;

/*-----------------
 * Match class
 *-----------------*/
static void _match_destroy(jw_match match)
{
    assert(match);

    if (match->jid)
    {
        jw_data_free(match->jid);
    }
    if (match->id)
    {
        jw_data_free(match->id);
    }
    if (match->typ)
    {
        jw_data_free(match->typ);
    }
    jw_data_free(match);
}

static bool _match_create(jw_dom_node *stanza,
                          const char *addr_attr, // {}to or {}from
                          jw_match   *match,
                          jw_err     *err)
{
    assert(stanza);
    assert(addr_attr);
    assert(match);

    const char *tmp;
    jw_match tmp_match = jw_data_malloc(sizeof(jw_match_t));
    if (!tmp_match)
    {
        JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
        return false;
    }
    memset(tmp_match, 0, sizeof(jw_match_t));
    tmp = jw_dom_get_attribute(stanza, addr_attr);
    if (tmp)
    {
        if (!(tmp_match->jid = jw_data_strdup(tmp)))
        {
            JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
            goto MATCH_CREATE_ERROR;
        }
    }
    tmp = jw_dom_get_attribute(stanza, "{}id");
    if (tmp)
    {
        if (!(tmp_match->id = jw_data_strdup(tmp)))
        {
            JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
            goto MATCH_CREATE_ERROR;
        }
    }
    tmp = jw_dom_get_localname(stanza);
    if (!(tmp_match->typ = jw_data_strdup(tmp)))
    {
        JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
        goto MATCH_CREATE_ERROR;
    }

    *match = tmp_match;
    return true;

 MATCH_CREATE_ERROR:
    _match_destroy(tmp_match);
    return false;
}

static unsigned int _match_hash(const void *key)
{
    assert(key);
    jw_match match = (jw_match)key;
    unsigned long h = 0;
    const char*   p;

    if (match->jid)
    {
        for(p = match->jid; *p != '\0'; p++)
        {
            h = (h << 5) - h + *p;
        }
    }
    for(p = match->id; *p != '\0'; p++)
    {
        h = (h << 5) - h + *p;
    }
    for(p = match->typ; *p != '\0'; p++)
    {
        h = (h << 5) - h + *p;
    }
    return (unsigned int) h;
}

static int _match_cmp(const void *key1, const void *key2)
{
    assert(key1);
    assert(key2);
    jw_match p1 = (jw_match)key1;
    jw_match p2 = (jw_match)key2;
    int r;
    // jid may be NULL, jw_strcmp is NULL-safe
    r = jw_strcmp(p1->jid, p2->jid);
    if (r)
    {
        return r;
    }
    r = jw_strcmp(p1->id, p2->id);
    if (r)
    {
        return r;
    }
    return jw_strcmp(p1->typ, p2->typ);
}

/*-----------------
 * Action class
 *-----------------*/
static void _action_call(jw_action action, jw_dom_node *response)
{
    assert(action);
    // response is NULL on timeout

    if (action->timeout)
    {
        event_free(action->timeout);
        action->timeout = NULL;
    }

    if (action->cb)
    {
        // this is the reason we have this whole file:
        action->cb(response, action->arg);
    }
    action->cb = NULL;
}

static void _action_destroy(jw_action action)
{
    assert(action);
    if (action->timeout)
    {
        event_free(action->timeout);
    }
    jw_data_free(action);
}

static void _action_clean(bool replace, bool destroy_key, void *key, void *data)
{
    UNUSED_PARAM(destroy_key);

    jw_match match = key;
    jw_action action = data;

    if (replace)
    {
        jw_log(JW_LOG_WARN, "Tracker action collision: (jid='%s', id='%s', type='%s')",
               match->jid,
               match->id,
               match->typ);
    }
    else
    {
        // true removal; be sure to trigger callback (as if we timed out)
        _match_destroy(match);
        _action_call(action, NULL);
    }
    _action_destroy(action);
}

static bool _action_create(jw_action *action, jw_err *err)
{
    assert(action);
    jw_action tmp = jw_data_malloc(sizeof(jw_action_t));
    if (!tmp)
    {
        JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
        return false;
    }
    memset(tmp, 0, sizeof(jw_match_t));

    *action = tmp;
    return true;
}

static void _elem_recv(jw_event_data event, void *arg)
{
    jw_dom_node  *stanza = event->data;
    jw_tracker   *tracker = arg;
    jw_match     match;
    jw_err       err;
    jw_action    action;
    const char  *typ;
    const char  *id;
    jw_hnode     *node;

    typ = jw_dom_get_attribute(stanza, "{}type");
    // if we've got type='result' or type='error' and we've got an id
    // attribute, it's a good candidate for tracking.
    // Note: don't add an ID to outbound presence, unless you want to
    // track it for errors for some reason.
    if (!typ)
    {
        return;
    }
    if ((jw_strncmp(typ, STR_RESULT, STR_RESULT_LEN) != 0) &&
        (jw_strncmp(typ, STR_ERROR, STR_ERROR_LEN) != 0))
    {
        return;
    }

    id = jw_dom_get_attribute(stanza, "{}id");
    if (!id)
    {
        return;
    }

    if (!_match_create(stanza, "{}from", &match, &err))
    {
        jw_log_err(JW_LOG_ERROR, &err, "Could not create match lookup.");
        return;
    }

    node = jw_htable_get_node(tracker->pending, match);
    if (node)
    {
        action = jw_hnode_get_value(node);
        _action_call(action, stanza);
        jw_htable_remove(tracker->pending, match);
    }
    _match_destroy(match);
}

JABBERWERX_API void jw_tracker_clear(jw_tracker *tracker)
{
    // clearing the table will trigger all of the callbacks with NULL
    jw_htable_clear(tracker->pending);
}

JABBERWERX_API bool jw_tracker_create(struct event_base *selector,
                                      jw_tracker **tracker,
                                      jw_err *err)
{
    assert(selector);
    assert(tracker);

    jw_tracker *tmp_tracker = jw_data_malloc(sizeof(jw_tracker_t));
    if (!tmp_tracker)
    {
        JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
        return false;
    }
    memset(tmp_tracker, 0, sizeof(jw_tracker_t));
    if (!jw_htable_create(TRACKER_HTABLE_SIZE,
                          _match_hash,
                          _match_cmp,
                          &tmp_tracker->pending,
                          err))
    {
        jw_data_free(tmp_tracker);
        return false;
    }
    // Get the initial id as a random number.  Odd that this doesn't
    // return an error.
    evutil_secure_rng_get_bytes((void*)&tmp_tracker->last_id,
                                sizeof(tmp_tracker->last_id));

    tmp_tracker->selector = selector;

    *tracker = tmp_tracker;
    return true;
}

JABBERWERX_API void jw_tracker_destroy(jw_tracker *tracker)
{
    jw_htable_destroy(tracker->pending);
    jw_data_free(tracker);
}

static void _track_timeout(evutil_socket_t fd, short what, void *arg)
{
    UNUSED_PARAM(fd);
    UNUSED_PARAM(what);
    jw_action action = arg;

    jw_hnode *node = jw_htable_get_node(action->tracker->pending, action->match);
    if (!node)
    {
        // Must have been some sort of race condition; we got the
        // response before the timer fired, and didn't cancel the
        // timer.  Almost an assert.
        jw_log(JW_LOG_WARN, "Unexpected timeout for (jid='%s', id='%s', type='%s')",
               action->match->jid,
               action->match->id,
               action->match->typ);
        return;
    }

    _action_call(action, NULL);
    jw_htable_remove(action->tracker->pending, action->match);
}

JABBERWERX_API bool jw_tracker_track(jw_tracker *tracker,
                                     jw_dom_node *request,
                                     jw_tracker_cb_func cb,
                                     void *arg,
                                     uint32_t timeout_sec,
                                     jw_err *err)
{
    assert(tracker);
    assert(request);
    assert(cb);
    jw_match  match = NULL;
    jw_action action = NULL;

    if (!_match_create(request, "{}to", &match, err))
    {
        return false;
    }
    if (!_action_create(&action, err))
    {
        goto TRACK_ERROR;
    }
    action->cb = cb;
    action->arg = arg;
    action->match = match;
    action->tracker = tracker;

    if (!match->id)
    {
        if (!(match->id = jw_data_malloc(UINT64_MAX_WIDTH)))
        {
            JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
            goto TRACK_ERROR;
        }
        snprintf(match->id, UINT64_MAX_WIDTH, "%" PRIu64, tracker->last_id++);
        if (!jw_dom_set_attribute(request, "{}id", match->id, err))
        {
            goto TRACK_ERROR;
        }
    }

    if (!jw_htable_put(tracker->pending,
                       match,
                       action,
                       _action_clean,
                       err))
    {
        goto TRACK_ERROR;
    }

    if (timeout_sec > 0)
    {
        struct timeval timeout = {timeout_sec, 0};
        if (!(action->timeout = evtimer_new(tracker->selector,
                                            _track_timeout,
                                            action)))
        {
            JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
            goto TRACK_ERROR_WITH_REMOVE;
        }

        if (evtimer_add(action->timeout, &timeout))
        {
            // most of the errors in evtimer_add are memory-related
            JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
            goto TRACK_ERROR_WITH_REMOVE;
        }
    }

    return true;

TRACK_ERROR_WITH_REMOVE:
    jw_htable_remove(tracker->pending, match);
    return false; //remove destroys match and action
TRACK_ERROR:
    _match_destroy(match); //match must exist to get here
    if (action)
    {
        _action_destroy(action);
    }
    return false;
}

JABBERWERX_API jw_event_notify_callback jw_tracker_get_callback()
{
    return _elem_recv;
}
