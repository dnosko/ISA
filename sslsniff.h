/*****************************************
 *              ISA 2020
 *        xnosko05 - Daša Nosková
 *        Monitoring SSL spojenia
 ****************************************/

#include <stdio.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>

#define OK 1
#define ERR_ARG 2

#define err_msg(msg, code) fprintf(stderr,"%s\n",msg); return code

void debug(char* text); //DELETE
int parse_arg(int argc, char **argv, char* interface, FILE* in_file);