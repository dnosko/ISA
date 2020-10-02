/*****************************************
 *              ISA 2020
 *        xnosko05 - Daša Nosková
 *        Monitoring SSL spojenia
 ****************************************/


#include <getopt.h>
#include "sslsniff.h"
#include "error.h"


int main(int argc, char **argv) {

    int return_code;
    char* interface = NULL;
    char* in_file = NULL;

    return_code = parse_arg(argc,argv, &interface, &in_file);

    FILE *fd;
    if (!(fd = fopen(in_file, "r")))
    {
        perror("Error while opening a file");
        err_msg(ERR_FILE, "");
    }

    fclose(fd);
    return return_code;
}

int parse_arg(int argc, char **argv, char** interface, char** in_file){
    int opt;
    bool i_used, r_used = false;

    while((opt = getopt(argc, argv, ":i:r:")) != -1)
    {
        switch(opt)
        {
            case 'i':
                debug("option: %c", opt);
                debug("interface: %s", optarg);
                i_used = true;
                *interface = optarg;
                break;
            case 'r':
                debug("option: %c", opt);
                debug("filename: %s", optarg);
                r_used = true;
                *in_file = optarg;
                break;
            case ':':
                err_msg(ERR_ARG,"Option needs value.");
            default:
                err_msg(ERR_ARG,"Unknown option: %c\n", optopt);
        }

    }

    if (r_used == false || i_used == false) {
        err_msg(ERR_ARG,"Options -r and -i are required.");
    }

    if (optind != argc) {
        debug("%d",optind);
        err_msg(ERR_ARG,"Extra arguments!");
    }

    return OK;
}

