/*****************************************
 *              ISA 2020
 *        xnosko05 - Daša Nosková
 *        Monitoring SSL spojenia
 ****************************************/

#ifndef ISA_ERROR_H
#define ISA_ERROR_H

#include <stdarg.h>
#include <stdio.h>

#define OK 0
#define ERR_ARG 1
#define ERR_FILE 2

#define err_msg(code, fmt, ...) fprintf(stderr,"" fmt "\n",##__VA_ARGS__); return(code)
#define debug(fmt,...) fprintf(stderr,"DEBUG: " fmt "\n",##__VA_ARGS__)


#endif //ISA_ERROR_H
