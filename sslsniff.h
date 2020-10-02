/*****************************************
 *              ISA 2020
 *        xnosko05 - Daša Nosková
 *        Monitoring SSL spojenia
 ****************************************/

#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <argp.h>
#include <string.h>
#include <stdbool.h>



int parse_arg(int argc, char **argv, char** interface, FILE** in_file);