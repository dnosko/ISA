/*****************************************
 *              ISA 2020
 *        xnosko05 - Daša Nosková
 *        Monitoring SSL spojenia
 ****************************************/


#include <getopt.h>
#include "sslsniff.h"
#include "error.h"
#include "analyser.h"


int main(int argc, char **argv) {

    int return_code;
    char* interface = NULL;
    char* in_file = NULL;

    return_code = parse_arg(argc,argv, &interface, &in_file);

    if(in_file != NULL)
        return_code = analyse_file_packets(in_file);

    return return_code;
}

int parse_arg(int argc, char **argv, char** interface, char** in_file){
    int opt;

    while((opt = getopt(argc, argv, ":i:r:")) != -1)
    {
        switch(opt)
        {
            case 'i':
                debug("option: %c", opt);
                debug("interface: %s", optarg);
                *interface = optarg;
                break;
            case 'r':
                debug("option: %c", opt);
                debug("filename: %s", optarg);

                /*  check extension  */
                const char *dot = strrchr(optarg,'.');
                debug("extension: %s", dot);
                if(!dot || dot == optarg || strcmp(dot,".pcapng") != 0) {
                    err_msg(ERR_FILE,"Extension must be pcapng");
                }

                *in_file = optarg;
                break;
            case ':':
                err_msg(ERR_ARG,"Option needs value.");
            default:
                err_msg(ERR_ARG,"Unknown option: %c", optopt);
        }

    }

    if (optind != argc) {
        debug("%d",optind);
        err_msg(ERR_ARG,"Extra arguments!");
    }

    return OK;
}

