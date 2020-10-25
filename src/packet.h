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

#ifndef SSLSNIFF_PACKET_H
#define SSLSNIFF_PACKET_H

#define ETHERNET_SIZE sizeof(struct ethhdr)
#define SSL_PORT 443

/* returns port number, takes tcp header and type="src" for source port and "dst" for destination port */
unsigned short get_port(struct tcphdr *tcph,char* type);
/* returns SYN if SYN flag is set and ACK not, returns FIN if FIN flag is set (client side) and empty string if other*/
char* check_flag(struct tcphdr *tcph);
/* returns IP adress, gets source if type = "src", destination if type = "dst" */
char* get_ip_addr(struct iphdr *iph, char* type);
/***********************************************/

/************************************************/
char convert_ascii(unsigned int val);
void print_packet(const u_char* packet, unsigned X, int no_bytes);
char* extract_data(const u_char* packet, unsigned from_B, unsigned to_B);
#endif //SSLSNIFF_PACKET_H
