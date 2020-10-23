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

#ifndef SSLSNIFF_PACKET_H
#define SSLSNIFF_PACKET_H

#define ETHERNET_SIZE sizeof(struct ethhdr)


void get_port(const u_char *packet,struct tcphdr *tcph,unsigned short *src_port);
/* returns SYN if SYN flag is set and ACK not, returns FIN if FIN flag is set (client side) and empty string if other*/
char* check_flag(struct tcphdr *tcph);

#endif //SSLSNIFF_PACKET_H
