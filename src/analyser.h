/*****************************************
 *              ISA 2020
 *        xnosko05 - Daša Nosková
 *        Monitoring SSL spojenia
 ****************************************/

#ifndef ISA_ANALYSER_H
#define ISA_ANALYSER_H

#include <bits/types/FILE.h>
#include <pcap/pcap.h>
#include <pcap.h>
#include <stdio.h>
#include <pcap/pcap.h>
#include <signal.h>
#include <stdbool.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include "packet.h"
#include "error.h"



#define CHECK_NULL_HANDLER if (handler == NULL) {perror("Null handler"); err_msg(ERR_PCAP,"");}
/* https://stackoverflow.com/questions/39624745/capture-only-ssl-handshake-with-tcpdump */

#define SSL_FILTER "tcp[((tcp[12] & 0xf0) >> 2)] = 0x16" // filter only SSL packets with handshake  hello??
#define TCP_FILTER "tcp"
#define HANDSHAKE_MSG 0x01 //starts at 6th B
#define MAX_TIME 101

typedef struct ssl_data {
    struct timeval* time; //start
    char* client_ip; //struct ip client_ip;
    unsigned client_port;
    char* server_ip;
    char* SNI;
    unsigned size_in_B;
    unsigned packets;
    unsigned long duration; //last - first packet
} Ssl_data;

Ssl_data* buffer;
unsigned buffer_len;


//void print_packet(const u_char* packet, unsigned X);

int open_handler(char* interface, char* pcap_file);
int analyse_file_packets(pcap_t* handler);
int analyse_interface_packets(pcap_t* handler,bpf_u_int32 pNet);
int ppcap_loop(pcap_t* handler);
int set_filter(pcap_t* handler,bpf_u_int32 netmask);
void process_packet(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet);
void init_item(unsigned short client_port,const struct pcap_pkthdr* pkthdr,struct iphdr *iph);
/* inserts data in buffer */
int append_item(Ssl_data* data);
/* looks for item in buffer based on port, returns NULL if buffer doesn't contain the item, returns position if found the item and -1 if not */
int find_item(unsigned short port);
int delete_item(unsigned short port);
void increment_count(unsigned short port);
/* prints connection */
void print_conn(Ssl_data data);

#endif //ISA_ANALYSER_H
