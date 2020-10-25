/*****************************************
 *              ISA 2020
 *        xnosko05 - Daša Nosková
 *        Monitoring SSL spojenia
 ****************************************/

#include <time.h>
#include "format.h"

char convert_ascii(unsigned int val) {
    char ascii_val[2];
    unsigned int decimal = val; //decimal
    if ((32 <= decimal && decimal < 127)) { //printable chars
        sprintf(ascii_val,"%c",val);
        debug("val %c\n",val);
        return ascii_val[0];
    }
    return '\0'; //non printable ascii
}

char* extract_data(const u_char* packet, unsigned from_B, unsigned len) {
    char* ascii_str = (char*) malloc(sizeof(char)*len+1);
    int pos = 0;
    unsigned end_sni = from_B+len;
    char ret_val = 0;
    for(unsigned i = from_B; i < end_sni; i++) {
        //debug"packet %02X\n", (unsigned int) packet[i]);
        ret_val = convert_ascii((unsigned int) packet[i]);
        if (ret_val != '\0')
            ascii_str[pos] = ret_val;
        else
            ascii_str[pos] = '\0';
        pos++;
    }
    ascii_str[len] = '\0';
    debug("extract_data %s len: %d pos: %d\n",ascii_str,len,pos);
    return ascii_str;
}

void print_conn(Ssl_data data){

    // convert time
    struct tm* lt = localtime(&data.time.tv_sec);
    char time[MAX_TIME];
    // yyyy-mm-dd hh:mm:ss.usec
    strftime(time, MAX_TIME-1, "%Y-%m-%d %X", lt);
    printf("%s.%lu,", time,data.time.tv_usec); // time
    printf("%s,%d,%s,%s,",data.client_ip,data.client_port,data.server_ip,data.SNI); //ip addresses
    if (data.duration == -1) printf("%lu,%d,%c\n",data.size_in_B,data.packets,'-');
    else printf("%lu,%d,%.3f\n",data.size_in_B,data.packets,data.duration);
}