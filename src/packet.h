/*****************************************
 *              ISA 2020
 *        xnosko05 - Daša Nosková
 *        Monitoring SSL spojenia
 ****************************************/

#include <zconf.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/if_ether.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdbool.h>

#include "format.h"

#ifndef SSLSNIFF_PACKET_H
#define SSLSNIFF_PACKET_H

#define ETHERNET_SIZE sizeof(struct ethhdr)
#define SSL_PORT 443
#define MILLI 1000 // to get milliseconds
#define CIPHER_LEN 76 //76th and 77th B
#define SNI_EXT_OFFSET 9 // 9 bytes to get from type of extention to SNI name
#define MIN_TCPHDR 20 // minimal size of tcp header is 20B
#define SNI_TYPE 0x00
#define IPV4 45 // ipv4 version in packet
#define VERSION 0 //version at 0th B

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
    bool client_hello; // used to remove not ssl packets from buffer
} Ssl_data;

/*returns ip version, 4 if ipv4, 6 if ipv6*/
int get_ip_version(u_char* packet);
/* gets tcp header size*/
int get_tcphdr_size(const u_char* packet, unsigned iphdrlen);
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
/* adds and finds SNI */
void add_sni(u_char* payload, int pos, Ssl_data* buffer);
/* extracts SNI from datagram */
char* get_SNI(const u_char* packet, unsigned from_B, unsigned len);


#endif //SSLSNIFF_PACKET_H
