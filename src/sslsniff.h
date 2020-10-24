/*****************************************
 *              ISA 2020
 *        xnosko05 - Daša Nosková
 *        Monitoring SSL spojenia
 ****************************************/

#include <ctype.h>
#include <argp.h>
#include <getopt.h>
#include "error.h"
#include "analyser.h"


int parse_arg(int argc, char **argv, char** interface, char** in_file);