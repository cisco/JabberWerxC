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

#ifndef SIMPLECLIENT_OPTION_PARSER_H
#define SIMPLECLIENT_OPTION_PARSER_H

#include <jabberwerx/util/htable.h>
#include <stdbool.h>

// parses commandline and populates given variables.
// returns false if the program should exit after this function returns.
bool parseCommandline (int argc, char * argv[],
        char **jid, char **password, char **streamType, char **hostname,
        char **port, char **uri, int *verbosity);

#endif // SIMPLECLIENT_OPTION_PARSER_H
