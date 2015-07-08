/**
 * \file
 * \brief
 * Parses the simpleclient commandline
 *
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2011 Cisco Systems, Inc.  All Rights Reserved.
 */

#define _GNU_SOURCE
#include <unistd.h>
#include <getopt.h>
#include <string.h>

#include <jabberwerx/util/log.h>
#include <jabberwerx/util/str.h>
#include <jabberwerx/client.h>

#include "option_parser.h"


/////////////////////////////////////////////
// internal functions
//
static void _usage (char *execPath)
{
    // find base program name in execpath
    const char * lastSlash = strrchr(execPath, '/');
    const char * progName;
    if (NULL == lastSlash)
    {
        progName = execPath;
    }
    else
    {
        progName = lastSlash + 1;
    }

    printf("USAGE: %s [-hv] <user_jid> <password> [ <stream type> "
           "{ [<hostname> [<port>]] | <uri> } ]\n\n", progName);
    printf(
"PARAMETERS:\n"
"    <user_jid>        user id to use for authentication\n"
"    <password>        user's password\n"
"    <stream type>     either 'bosh' or 'socket'\n"
"    if <stream type> is socket:\n"
"        <hostname>    hostname of XMPP server (defaults to jid domain)\n"
"        <port>        port of XMPP server (defaults to 5222)\n"
"    if <stream type> is bosh:\n"
"        <uri>         uri to the XMPP server.\n"
"\n"
"OPTIONS:\n"
"  -h, --help      Show this help text.\n"
"  -v, --verbose   Increases the verbosity of the logging.  This option can\n"
"                  be specified multiple times for more logging verbosity.\n"
"                  Specify this option at least once to see a real-time dump\n"
"                  of the protocol nodes.\n"
"\n"
"EXAMPLES:\n");
    printf("  %s test1@example.com test socket 10.94.0.138 5222\n",
           progName);
    printf("  %s -vvv test2@localhost test\n", progName);
    printf("  %s test2@localhost test -vvv\n", progName);
    printf("  %s testuser@example.com test bosh http://10.94.0.138:5280\n",
           progName);
}

/////////////////////////////////////////////
// parse_commandline
//
bool parseCommandline (int argc, char * argv[],
        char **jid, char **password, char **streamType, char **hostname,
        char **port, char **uri, int *verbosity)
{
    char *hostnameOrUri = NULL;
    char **params[] = { jid, password, streamType, &hostnameOrUri, port, NULL };

    const char * shortOpts = "hv";
    const struct option longOpts[] =
    {
        {"help",    no_argument, NULL, 'h'},
        {"verbose", no_argument, NULL, 'v'},
        {NULL, 0, NULL, 0}
    };

    int option;
    while (-1 < (option = getopt_long(argc, argv, shortOpts, longOpts, NULL)))
    {
        switch (option) {
        case 'h':
            _usage(argv[0]);
            return false;

        case 'v':
            if (*verbosity <= JW_LOG_DEBUG)
            {
                ++*verbosity;
            }
            break;

        default:
            // error message has already been printed by getopt_long
            return false;
        }
    }
    
    // ensure optional parameters are initialized
    *streamType = NULL;
    *hostname   = NULL;
    *port       = NULL;
    *uri        = NULL;
    
    // read in positional parameters
    for (int argIdx = optind; argIdx < argc; ++argIdx)
    {
        int paramIdx = argIdx - optind;
        
        if (!params[paramIdx])
        {
            jw_log(JW_LOG_ERROR, "too many parameters");
            _usage(argv[0]);
            return false;
        }
        
        *(params[paramIdx]) = argv[argIdx];
    }

    if (!*password)
    {
        jw_log(JW_LOG_ERROR, "too few parameters");
        _usage(argv[0]);
        return false;
    }
    
    // figure out what hostnameOrUri should be and normalize streamType
    if (0 == jw_strcasecmp(*streamType, JW_CLIENT_CONFIG_STREAM_TYPE_BOSH))
    {
        *streamType = JW_CLIENT_CONFIG_STREAM_TYPE_BOSH;
        *uri = hostnameOrUri;
        
        if (!*uri)
        {
            jw_log(JW_LOG_ERROR, "a uri must be specified for bosh streams");
            return false;
        }
    }
    else
    {
        if (*streamType)
        {
            if (0 == strcasecmp(*streamType,
                                JW_CLIENT_CONFIG_STREAM_TYPE_SOCKET))
            {
                *streamType = JW_CLIENT_CONFIG_STREAM_TYPE_SOCKET;
            }
            else
            {
                jw_log(JW_LOG_ERROR, "invalid stream type: '%s'", *streamType);
                return false;
            }
        }

        *hostname = hostnameOrUri;
    }
    
    return true;
}
