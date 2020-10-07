/*****************************************
 *              ISA 2020
 *        xnosko05 - Daša Nosková
 *        Monitoring SSL spojenia
 ****************************************/

#ifndef ISA_ANALYSER_H
#define ISA_ANALYSER_H

#include <bits/types/FILE.h>
#include "error.h"
#include <pcap/pcap.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <string.h>


#define ETHERNET_SIZE sizeof(struct ethhdr)

int analyse_interface_packets();
int analyse_file_packets(char* pcap_file);
void process_packet(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet);
void check_protocol(const u_char *packet,  struct iphdr *iph, unsigned short *src_port,
                    unsigned short *dst_port);
void get_port(const u_char *packet,struct iphdr *iph, char *type, unsigned short *src_port,
              unsigned short *dst_port);
void get_src_dst_addr(char *src, char *dst, struct iphdr *iph);


#endif //ISA_ANALYSER_H
