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


void get_port(const u_char *packet,struct iphdr *iph,unsigned short *src_port);

#endif //SSLSNIFF_PACKET_H
