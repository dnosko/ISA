/*****************************************
 *              ISA 2020
 *        xnosko05 - Daša Nosková
 *        Monitoring SSL spojenia
 ****************************************/

#include "sslsniff.h"


int main(int argc, char **argv) {

    int return_code;
    char* interface = NULL;
    char* in_file = NULL;


    return_code = parse_arg(argc,argv, &interface, &in_file);
    if(return_code != OK)
        return return_code;

    return open_handler(interface,in_file);

}

int parse_arg(int argc, char **argv, char** interface, char** in_file){
    int opt;

    while((opt = getopt(argc, argv, ":i:r:")) != -1)
    {
        switch(opt)
        {
            case 'i':
                *interface = optarg;
                break;
            case 'r':

                debug("filename: %s", optarg);
                /*  check extension  */
                char *dot = strrchr(optarg,'.');

                if(!dot || dot == optarg || strcmp(dot,".pcapng") != 0) {
                    err_msg(ERR_FILE,"Extension must be pcapng");
                }

                *in_file = optarg;
                break;
            case ':':
                err_msg(ERR_ARG,"Option needs value.");
            default:
                printf("Usage: -i interface -r file\n");
        }

    }

    if (optind != argc) {
        err_msg(ERR_ARG,"Extra arguments!");
    }

    return OK;
}

