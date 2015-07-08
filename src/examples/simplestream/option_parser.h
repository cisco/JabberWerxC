/**
 * \file
 * \brief
 * Parses the simplestream commandline
 *
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2011 Cisco Systems, Inc.  All Rights Reserved.
 */

#ifndef SIMPLESTREAM_OPTION_PARSER_H
#define SIMPLESTREAM_OPTION_PARSER_H

#include <jabberwerx/util/htable.h>
#include <stdbool.h>

// parses commandline and populates given variables.
// returns false if the program should exit after this function returns.
bool parseCommandline (int argc, char * argv[],
        char **jid, char **password, char **streamType, char **hostname,
        char **port, char **uri, int *verbosity);

#endif // SIMPLESTREAM_OPTION_PARSER_H
