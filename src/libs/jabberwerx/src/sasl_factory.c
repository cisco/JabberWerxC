/**
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

#include "include/sasl_int.h"
#include <jabberwerx/sasl_factory.h>
#include <jabberwerx/util/log.h>
#include <jabberwerx/util/str.h>
#include <assert.h>
#include <string.h>

#define NUM_EXPECTED_MECHANISMS 5


struct _jw_sasl_factory
{
    // TODO: perhaps use an ordered dict when it becomes available...
    jw_htable    *mech_names_set;
    jw_sasl_mech *mechs; // in priority order
};


JABBERWERX_API bool jw_sasl_factory_create(jw_htable        *config,
                                           jw_sasl_factory **factory,
                                           jw_err          *err)
{
    UNUSED_PARAM(config);

    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    assert(factory);

    size_t factory_size = sizeof(struct _jw_sasl_factory);
    jw_sasl_factory *ret_factory = jw_data_malloc(factory_size);
    if (NULL == ret_factory)
    {
        jw_log_err(JW_LOG_WARN, err, "failed to allocate sasl factory");
        JABBERWERX_ERROR(err, JW_ERR_NO_MEMORY);
        return false;
    }

    memset(ret_factory, 0, factory_size);

    if (!jw_htable_create(NUM_EXPECTED_MECHANISMS,
                          jw_strcase_hashcode, jw_strcase_compare,
                          &ret_factory->mech_names_set, err))
    {
        jw_log_err(JW_LOG_WARN, err,
                   "failed to allocate sasl factory names set");
        jw_data_free(ret_factory);
        return false;
    }

    jw_log(JW_LOG_DEBUG, "allocated sasl factory %p", (void *)ret_factory);
    *factory = ret_factory;

    return true;
}

JABBERWERX_API void jw_sasl_factory_destroy(jw_sasl_factory *factory)
{
    JW_LOG_TRACE_FUNCTION("factory=%p", (void *)factory);

    assert(factory);
    
    jw_htable_destroy(factory->mech_names_set);

    while (factory->mechs)
    {
        jw_sasl_mech *next = factory->mechs->next;
        jw_sasl_mech_destroy(factory->mechs);
        factory->mechs = next;
    }

    jw_data_free(factory);
}

JABBERWERX_API void jw_sasl_factory_htable_cleaner(bool replace,
                                                   bool destroy_key,
                                                   void *key,
                                                   void *data)
{
    JW_LOG_TRACE_FUNCTION_NO_ARGS;

    UNUSED_PARAM(replace);
    UNUSED_PARAM(destroy_key);
    UNUSED_PARAM(key);

    jw_sasl_factory_destroy(data);
}

JABBERWERX_API bool jw_sasl_factory_add_mech(jw_sasl_factory *factory,
                                             jw_sasl_mech    *mech,
                                             jw_err         *err)
{
    JW_LOG_TRACE_FUNCTION("factory=%p; mech=%p(%s)", (void *)factory,
                          (void *)mech, mech ? mech->name : "null");

    assert(factory);
    assert(mech);
    assert(!mech->next); // weak check to detect multiple factory parents
    
    // if a mech with the same name already added, error out
    if (NULL != jw_htable_get_node(factory->mech_names_set, mech->name))
    {
        jw_log(JW_LOG_DEBUG, "mechanism already registered: '%s'", mech->name);
        JABBERWERX_ERROR(err, JW_ERR_INVALID_ARG);
        return false;
    }

    // register mech name in mech_names_set
    if (!jw_htable_put(factory->mech_names_set, mech->name, NULL, NULL, err))
    {
        jw_log(JW_LOG_WARN, "failed to record mech name in set");
        return false;
    }

    // add mechanism to the head of the list, making it the most preferred mech
    mech->next = factory->mechs;
    factory->mechs = mech;

    return true;
}

JABBERWERX_API bool jw_sasl_factory_get_best_mech_in_dom(
                        jw_sasl_factory        *factory,
                        jw_dom_node            *choices,
                        jw_htable              *config,
                        jw_sasl_mech_instance **instance,
                        jw_err                *err)
{
    JW_LOG_TRACE_FUNCTION("factory=%p", (void *)factory);

    assert(factory);
    assert(choices);
    assert(instance);

    if (JW_DOM_TYPE_ELEMENT != jw_dom_get_nodetype(choices))
    {
        jw_log(JW_LOG_WARN, "choices is not a valid node type");
        JABBERWERX_ERROR(err, JW_ERR_INVALID_ARG);
        return false;
    }

    jw_log_dom(JW_LOG_TRACE, choices, "mechanism choices: ");

    const char *ename = jw_dom_get_ename(choices);
    jw_dom_node *choice = NULL;
    bool check_siblings;
    if (0 == jw_strcmp(SASL_MECHANISMS, ename))
    {
        check_siblings = true;
        choice = jw_dom_get_first_element(choices, "mechanism");
    }
    else if (0 == jw_strcmp(SASL_MECHANISM, ename))
    {
        check_siblings = false;
        choice = choices;
    }

    if (NULL == choice)
    {
        jw_log_dom(JW_LOG_WARN, choices,
                   "choices does not contain any mechanisms: ");
        JABBERWERX_ERROR(err, JW_ERR_INVALID_ARG);
        return false;
    }

    jw_htable *choice_set;
    if (!jw_htable_create(NUM_EXPECTED_MECHANISMS,
                          jw_strcase_hashcode, jw_strcase_compare,
                          &choice_set, err))
    {
        jw_log(JW_LOG_WARN, "failed to create mech name choices set");
        return false;
    }

    do
    {
        const char *name;

        if (JW_DOM_TYPE_ELEMENT != jw_dom_get_nodetype(choice)
         || 0 != jw_strcmp(SASL_MECHANISM, jw_dom_get_ename(choice))
         || NULL == (name = jw_dom_get_first_text(choice)))
        {
            int typ = jw_dom_get_nodetype(choice);
            if (JW_DOM_TYPE_ELEMENT != typ)
            {
                jw_log(JW_LOG_DEBUG, "skipping invalid choice (type: %d)", typ);
            }
            else
            {
                jw_log_dom(JW_LOG_DEBUG, choice, "skipping invalid choice: ");
            }
        }
        else
        {
            jw_log(JW_LOG_DEBUG, "adding choice: '%s'", name);

            if (!jw_htable_put(choice_set, name, NULL, NULL, err))
            {
                jw_log(JW_LOG_WARN, "failed to record mech name in set");
                jw_htable_destroy(choice_set);
                return false;
            }
        }

        choice = jw_dom_get_sibling(choice);
    } while (check_siblings && NULL != choice);

    bool ret = jw_sasl_factory_get_best_mech_in_set(factory, choice_set,
                                                    config, instance, err);

    jw_htable_destroy(choice_set);
    return ret;
}

JABBERWERX_API bool jw_sasl_factory_get_best_mech_in_set(
                        jw_sasl_factory        *factory,
                        jw_htable              *choices,
                        jw_htable              *config,
                        jw_sasl_mech_instance **instance,
                        jw_err                *err)
{
    UNUSED_PARAM(err);

    JW_LOG_TRACE_FUNCTION("factory=%p", (void *)factory);

    assert(factory);
    assert(choices);
    assert(instance);

    jw_sasl_mech_instance *ret_inst = NULL;

    jw_sasl_mech *mech = factory->mechs;
    while (mech)
    {
        jw_log(JW_LOG_TRACE, "probing choices for mech: '%s'", mech->name);

        if (NULL != jw_htable_get_node(choices, mech->name))
        {
            jw_log(JW_LOG_DEBUG, "attempting to instantiate mech: '%s'",
                   mech->name);

            // in general, don't propagate errors from here to caller
            jw_err err_int;
            if (jw_sasl_mech_instance_create(config, mech, &ret_inst, &err_int))
            {
                break;
            }

            if (JW_ERR_NO_MEMORY == err_int.code)
            {
                jw_log_err(JW_LOG_WARN, &err_int,
                           "unable to instantiate mech: '%s'", mech->name);

                if (err)
                {
                    *err = err_int;
                }
                return false;
            }

            jw_log_err(JW_LOG_DEBUG, &err_int,
                       "unable to instantiate mech: '%s'", mech->name);
        }

        mech = mech->next;
    }

    *instance = ret_inst;
    return true;
}

JABBERWERX_API bool jw_sasl_factory_iter_begin(jw_sasl_factory       *factory,
                                               jw_sasl_factory_iter *iter,
                                               jw_err               *err)
{
    UNUSED_PARAM(err);

    JW_LOG_TRACE_FUNCTION("factory=%p; iter=%p", (void *)factory, (void *)iter);

    assert(factory);
    assert(iter);

    *iter = factory->mechs;

    return true;
}

JABBERWERX_API bool jw_sasl_factory_iter_next(jw_sasl_factory_iter *iter,
                                              jw_sasl_mech         **mech,
                                              jw_err               *err)
{
    UNUSED_PARAM(err);

    JW_LOG_TRACE_FUNCTION("iter=%p", (void *)iter);

    assert(iter);
    assert(mech);

    jw_sasl_mech *ret_mech = *iter;
    if (NULL != ret_mech)
    {
        *iter = (*iter)->next;
    }

    *mech = ret_mech;
    return true;
}
