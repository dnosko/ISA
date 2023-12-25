/*****************************************
 *              ISA 2020
 *        xnosko05 - Daša Nosková
 *        Monitoring SSL spojenia
 ****************************************/

#ifndef ISA_ANALYSER_H
#define ISA_ANALYSER_H


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



#define CHECK_NULL_HANDLER if (handler == NULL) {perror("Null handler"); return ERR_PCAP;}

#define TCP_FILTER "tcp"
#define OFFSET 5 // size of ssl header is SSL length plus 5 B before length information
#define CONTENT_B 0 // content type at 0 B /* INDEXING FROM 0 */
#define VERSION_B 1 // version at 1st and 2nd B
#define SSL_LEN 3 // length of ssl packet at 3rd and 4th B
#define HANDSHAKE_B 5 // handshake type at 5th B
#define CLIENT_HELLO 0x01 //starts at 6th B
#define SERVER_HELLO 0x02
#define CIPHER 0x14
#define ALERT 0x15
#define HANDSHAKE 0x16
#define APP_DATA 0x17
#define IPv6_HDR 40
#define IPV4_LEN 32 // ip is 32b
#define IPV6_LEN 128 //ips is 128b

#define NOT_FOUND -1

typedef struct ip_addrs {
    union Version_src {
        char src_6[IPV6_LEN];
        char src_4[IPV4_LEN];
    } version_src;
    union Version_dst {
        char dst_6[IPV6_LEN];
        char dst_4[IPV4_LEN];
    } version_dst;
} Ip_addr;


int open_handler(char* interface, char* pcap_file);
int analyse_file_packets(pcap_t* handler);
int analyse_interface_packets(pcap_t* handler,bpf_u_int32 pNet);
int start_packet_processing(pcap_t* handler);
/* clean unused items from buffer */
void clean_buffer(unsigned int len);
int set_filter(pcap_t* handler,bpf_u_int32 netmask);
void process_packet(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet);
/* process messages from client, port = client's port*/
void process_client(u_char *payload, struct tcphdr *tcp, const struct pcap_pkthdr *pkthdr, Ssl_data *ssl);
/* process messages from server */
void process_server(struct tcphdr *tcp, u_char *payload);
/* init new connection*/
Ssl_data init_item(unsigned short client_port, unsigned short server_port, Ip_addr *ip, const struct pcap_pkthdr *pkthdr);
/* finalizes the connection, gets duration and prints the connection */
void finish(unsigned pos, struct timeval ts);
/* inserts data in buffer */
int append_item(Ssl_data* data);
/* looks for item in buffer based on port, returns NULL if buffer doesn't contain the item, returns position if found the item and -1 if not */
int find_item(unsigned short port);
/*deletes item from buffer at pos*/
int delete_item(int pos);
/* increments number of packets in given ssl connection*/
void increment_count_packets(int pos);
/* adds length of bytes from ssl header */
void increment_bytes(int pos, u_char* payload);

#endif //ISA_ANALYSER_H
