/*****************************************
 *              ISA 2020
 *        xnosko05 - Daša Nosková
 *        Monitoring SSL spojenia
 ****************************************/

#include <zconf.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdbool.h>

#ifndef SSLSNIFF_PACKET_H
#define SSLSNIFF_PACKET_H

#define ETHERNET_SIZE sizeof(struct ethhdr)
#define SSL_PORT 443
#define MILLI 1000 // to get milliseconds
#define CIPHER_LEN 76 //76th and 77th B
#define SNI_EXT_OFFSET 9 // 9 bytes to get from type of extention to SNI name

typedef struct ssl_data {
    struct timeval time; //start
    char* client_ip; //struct ip client_ip;
    unsigned client_port;
    char* server_ip;
    char* SNI;
    unsigned long size_in_B;
    unsigned packets;
    float duration; //last - first packet
    bool server_hello;
} Ssl_data;


/* returns port number, takes tcp header and type="src" for source port and "dst" for destination port */
unsigned short get_port(struct tcphdr *tcph,char* type);
/* returns SYN if SYN flag is set and ACK not, returns FIN if FIN flag is set (client side) and empty string if other*/
char* check_flag(struct tcphdr *tcph);
/* returns IP adress, gets source if type = "src", destination if type = "dst" */
void get_ip_addr(struct iphdr *iph, char *src, char *dst);
/* returns length from ssl header*/
int get_len(u_char* payload, int position);
/* returns duration in seconds with precision on milliseconds  */
float get_duration(struct timeval start, struct timeval end);
/* gets position of SNI extention */
int get_ext_pos(u_char* payload);

#endif //SSLSNIFF_PACKET_H
