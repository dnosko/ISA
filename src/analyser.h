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
#include <netinet/ip.h>
#include <string.h>
#include <pcap/pcap.h>
#include <signal.h>
#include <stdbool.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "packet.h"



#define CHECK_NULL_HANDLER if (handler == NULL) {perror("Null handler"); err_msg(ERR_PCAP,"");}
/* https://stackoverflow.com/questions/39624745/capture-only-ssl-handshake-with-tcpdump */

#define SSL_FILTER "tcp[((tcp[12] & 0xf0) >> 2)] = 0x16" // filter only SSL packets with handshake  hello??
#define TCP_FILTER "tcp"
#define HANDSHAKE_MSG 0x01 //starts at 6th B
#define MAX_TIME 101

typedef struct ssl_data {
    struct timeval* time; //start //TODO upravit na tm strukturu atd
    struct ip client_ip;
    unsigned client_port;
    struct ip server_ip;
    char* SNI;
    unsigned size_in_B;
    unsigned packets;
    unsigned long duration; //last - first packet
} Ssl_data;

Ssl_data* buffer;
unsigned buffer_len;


void print_packet(const u_char* packet, unsigned X);

void convert_ascii(char *ascii_str, unsigned int val);
int open_handler(char* interface, char* pcap_file);
int analyse_file_packets(pcap_t* handler);
int analyse_interface_packets(pcap_t* handler,bpf_u_int32 pNet);
int ppcap_loop(pcap_t* handler);
int set_filter(pcap_t* handler,bpf_u_int32 netmask);
void process_packet(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet);
/* inserts data in buffer */
int append_item(Ssl_data data);
/* looks for item in buffer based on port, returns NULL if buffer doesn't contain the item, returns position if found the item and -1 if not */
int find_item(unsigned short port, Ssl_data* item);
int delete_item(unsigned short port);
// converts in_time from seconds to real time
void get_timestamp(struct tm* time,struct timeval in_time);
void check_protocol(const u_char *packet,  struct iphdr *iph, unsigned short *src_port,
                    unsigned short *dst_port);
void get_src_dst_addr(char *src, char *dst, struct iphdr *iph);
char* extract_data(const u_char* packet, unsigned from_B, unsigned to_B);

#endif //ISA_ANALYSER_H
