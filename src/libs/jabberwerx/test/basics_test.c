/**
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

#include <string.h>
#include <jabberwerx/basics.h>
#include "fct.h"


static bool _check_format(const char *ver_str, int num_labels)
{
    if (!ver_str)
    {
        return false;
    }

    int dots_found = 0;
    for (const char *cur = ver_str; *cur; ++cur)
    {
        if ('.' == *cur)
        {
            ++dots_found;
            continue;
        }

        if ('0' > *cur || '9' < *cur)
        {
            return false;
        }
    }

    return num_labels - 1 == dots_found;
}


FCTMF_SUITE_BGN(basics_test)
{
    FCT_TEST_BGN(jw_basics_version)
    {
        fct_chk(_check_format(jw_version(false), 2));
        fct_chk(_check_format(jw_version(true), 3));
    } FCT_TEST_END()
} FCTMF_SUITE_END()
