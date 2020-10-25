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
#include "format.h"



#define CHECK_NULL_HANDLER if (handler == NULL) {perror("Null handler"); err_msg(ERR_PCAP,"");}
/* https://stackoverflow.com/questions/39624745/capture-only-ssl-handshake-with-tcpdump */

#define SSL_FILTER "tcp[((tcp[12] & 0xf0) >> 2)] = 0x16" // filter only SSL packets with handshake  hello??
#define TCP_FILTER "tcp"
#define CONTENT_B 0 // content type at 0 B
#define VERSION_B 1 // version at 1st and 2nd B
#define SSL_LEN 3 // length of ssl packet at 3rd and 4th B
#define SNI_LEN 125 // 125-126th B - length of SNI
#define HANDSHAKE_B 5 // handshake type at 5th B
#define CLIENT_HELLO 0x01 //starts at 6th B
#define SERVER_HELLO 0x02
#define HANDSHAKE 0x16
#define APP_DATA 0x17

#define TCPHDRLEN  32


Ssl_data* buffer;
unsigned buffer_len;


//void print_packet(const u_char* packet, unsigned X);

int open_handler(char* interface, char* pcap_file);
int analyse_file_packets(pcap_t* handler);
int analyse_interface_packets(pcap_t* handler,bpf_u_int32 pNet);
int ppcap_loop(pcap_t* handler);
int set_filter(pcap_t* handler,bpf_u_int32 netmask);
void process_packet(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet);
/* process messages from client, port = client's port*/
void process_client(unsigned short port,const struct pcap_pkthdr* pkthdr,u_char* payload,struct iphdr* iph,struct tcphdr* tcp);
/* process messages from server */
void process_server(struct tcphdr* tcp, u_char* payload,const struct pcap_pkthdr* pkthdr);
void init_item(unsigned short client_port,const struct pcap_pkthdr* pkthdr,struct iphdr *iph,u_char* payload);
/* finds sni */
void add_sni(u_char *payload, unsigned short port);
/* inserts data in buffer */
int append_item(Ssl_data* data);
/* looks for item in buffer based on port, returns NULL if buffer doesn't contain the item, returns position if found the item and -1 if not */
int find_item(unsigned short port);
int delete_item(unsigned short port);
/* increments number of packets in given ssl connection and adds length of bytes from ssl header*/
void increment_count(unsigned short port,u_char* payload);

#endif //ISA_ANALYSER_H
