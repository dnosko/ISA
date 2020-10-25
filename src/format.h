/*****************************************
 *              ISA 2020
 *        xnosko05 - Daša Nosková
 *        Monitoring SSL spojenia
 ****************************************/

#include <zconf.h>
#include <stdlib.h>
#include <stdio.h>
#include "error.h"
#include "packet.h"

#define MAX_TIME 101

#ifndef SSLSNIFF_FORMAT_H
#define SSLSNIFF_FORMAT_H

char convert_ascii(unsigned int val);
char* extract_data(const u_char* packet, unsigned from_B, unsigned len);
/* prints connection */
void print_conn(Ssl_data data);

#endif //SSLSNIFF_FORMAT_H
