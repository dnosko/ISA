/*****************************************
 *              ISA 2020
 *        xnosko05 - Daša Nosková
 *        Monitoring SSL spojenia
 ****************************************/


#include <getopt.h>
#include "sslsniff.h"

int main(int argc, char **argv) {
    char* interface = "";
    FILE *in_file = NULL;

    return parse_arg(argc, argv, interface, in_file);
}

int parse_arg(int argc, char **argv, char* interface, FILE* in_file) {

    if (argc > 3) {
        err_msg("Too many arguments!",ERR_ARG);
    }
    else if (argc < 3) {
        err_msg("Missing arguments!",ERR_ARG);
    }

    int opt;
    while((opt = getopt(argc, argv,"ir:")) != -1) {
        switch(opt) {
            case 'i':
                interface = optarg;
                if (optarg == NULL) {
                    err_msg("Interface not specified.",ERR_ARG);
                }
                debug("hi");
                break;
            case 'r':
                //in_file = optarg;
                break;
            default:
                fprintf(stderr,"%s\n","Unknown parameter!");
        }
    }

    return OK;
}

void debug(char* text) {
    printf("%s\n",text);
}