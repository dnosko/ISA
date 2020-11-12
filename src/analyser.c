/*****************************************
 *              ISA 2020
 *        xnosko05 - Daša Nosková
 *        Monitoring SSL spojenia
 ****************************************/

#include <netinet/ip6.h>
#include "analyser.h"

/* DOKUMENTACIA ukoncenie ked pride FIN OD KLIENTA
 *
 * */
// verziu ssl urcuje server
//TODO <timestamp>,<client ip>,<client port>,<server ip>,<SNI>,<bytes>,<packets>,<duration sec>
/*TODO
 * KONTROLA VERZII -> ak nie je podporovana tak vypisat ze nie je podporovana na stderr a skip, 1.3 skip
 * KONTROLA CI DANE ROZHRANIE EXISTUJE
*/

Ssl_data* buffer;
unsigned buffer_len;


int open_handler(char* interface, char* pcap_file) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handler;
    int return_code;


    //init buffer
    buffer = (Ssl_data*)malloc(sizeof(Ssl_data));
    if (!buffer){
        err_msg(ERR_MEMORY, "Allocation failed.");
    }

    if(pcap_file != NULL){
        //open file
        handler = pcap_open_offline(pcap_file, errbuf);
        CHECK_NULL_HANDLER
        return_code = analyse_file_packets(handler);
        pcap_close(handler);

        if (return_code != OK) {
            return return_code;
        }
    }

    if(interface != NULL) {
        bpf_u_int32 pMask;            /* subnet mask */
        bpf_u_int32 pNet;             /* ip address*/


        if (pcap_lookupnet(interface, &pNet, &pMask, errbuf) == -1) {
            err_msg( "Error: %s", errbuf);
            return ERR_PCAP;
        }

        handler = pcap_open_live(interface, BUFSIZ, 0, -1, errbuf);
        CHECK_NULL_HANDLER
        analyse_interface_packets(handler, pNet);

        pcap_close(handler);

    }


    return OK;
}

int analyse_file_packets(pcap_t* handler){

    if (set_filter(handler,PCAP_NETMASK_UNKNOWN) == ERR_PCAP)
        return ERR_PCAP;

    return ppcap_loop(handler);
}

int analyse_interface_packets(pcap_t* handler,bpf_u_int32 pNet) {

    if (set_filter(handler,pNet) == ERR_PCAP){
        return ERR_PCAP;
    }

    return ppcap_loop(handler);
}

int ppcap_loop(pcap_t* handler){
    int infinite_loop = -1;

    int return_code = pcap_loop(handler,infinite_loop, process_packet, NULL);
    if (return_code == PCAP_ERROR || return_code == PCAP_ERROR_BREAK ) {
        //pcap_close(handler);
        return return_code;
    }

    unsigned i;

    while(buffer_len != 0) {
        i = buffer_len-1;
        delete_item(i);
    }

    return OK;
}

int set_filter(pcap_t* handler,bpf_u_int32 netmask) {
    struct bpf_program fp;        /* to hold compiled program */

    // apply ssl filter
    if(pcap_compile(handler, &fp,TCP_FILTER, 0, netmask) == -1)
    {
        perror("ERR:");
        printf("\npcap_compile() failed\n");
        pcap_close(handler);
        return ERR_PCAP;
    }
    if(pcap_setfilter(handler, &fp) == -1)
    {
        printf("\npcap_setfilter() failed\n");
        pcap_close(handler);
        return ERR_PCAP;
    }

    return OK;
}

void process_packet(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet) {

    struct iphdr* iph;
    struct ip6_hdr* ip6_hdr;
    unsigned short iphdrlen;
    u_char *payload; /* Packet payload */
    int tcpheader_size;
    unsigned short src_port,dst_port;
    int ip_version;
    Ip_addr ip;

    ip_version = get_ip_version(packet);

    if (ip_version == 6) { //ipv6
        ip6_hdr = (struct ip6_hdr *)(packet + ETHERNET_SIZE);
        iphdrlen = IPv6_HDR;
        ip.src = (char*) malloc(sizeof(char)*IPV6_LEN);
        ip.dst = (char*) malloc(sizeof(char)*IPV6_LEN);
        get_ipv6_addr(ip6_hdr,ip.src, ip.dst);
    }
    else { // ipv4
        iph = (struct iphdr*)(packet + ETHERNET_SIZE);
        iphdrlen = iph->ihl*4;
        // get source and destination ip address
        ip.src = (char*) malloc(sizeof(char)*IPV4_LEN);
        ip.dst = (char*) malloc(sizeof(char)*IPV4_LEN);
        get_ip_addr(iph, ip.src, ip.dst, 0);
    }


    struct tcphdr* tcp = (struct tcphdr*)(packet + iphdrlen + ETHERNET_SIZE);
    tcpheader_size = get_tcphdr_size(packet,iphdrlen);

    payload = (u_char *)(packet + ETHERNET_SIZE + iphdrlen + tcpheader_size ); // this is ssl payload

    src_port = get_port(tcp, "src");
    dst_port = get_port(tcp,"dst");

    int pos = find_item(src_port);

    if (((pos == NOT_FOUND && (!strcmp(check_flag(tcp),"SYN"))) || pos != NOT_FOUND)){
        process_client(src_port,dst_port, payload, &ip, tcp, pkthdr);
    }
    else { // source is SSL
        process_server(tcp, payload);
    }
}


void process_client(unsigned short src_port, unsigned short dst_port, u_char *payload, Ip_addr *ip, struct tcphdr *tcp,
                    const struct pcap_pkthdr *pkthdr) {

    char* flag = check_flag(tcp);

    if (!strcmp(flag,"SYN")) { // add new connection to buffer
        Ssl_data ssl = init_item(src_port, dst_port, ip, pkthdr);
        append_item(&ssl);
    }
    else {
        int pos = find_item(src_port);
        if (pos == NOT_FOUND) return;

        if((payload[CONTENT_B] == HANDSHAKE) && (payload[HANDSHAKE_B] == CLIENT_HELLO)) {
            buffer[pos].server_hello = true;
            add_sni(payload,pos,buffer);
        }

        increment_count(pos,payload);
        if (!strcmp(flag,"FIN")){
            finish(pos,pkthdr->ts);
        }
    }
}

void process_server(struct tcphdr *tcp, u_char *payload) {

    unsigned short client_port;
    int pos;

    client_port = get_port(tcp, "dst");

    pos = find_item(client_port);
    if (pos == NOT_FOUND) return;

    if((payload[CONTENT_B] == HANDSHAKE) && (payload[HANDSHAKE_B] == SERVER_HELLO)) {
        buffer[pos].server_hello = true;
    }

    increment_count(pos,payload);
}

Ssl_data init_item(unsigned short client_port, unsigned short server_port, Ip_addr *ip, const struct pcap_pkthdr *pkthdr) {

    Ssl_data ssl_connection;
    ssl_connection.client_port = client_port;
    ssl_connection.server_port = server_port;
    ssl_connection.time.tv_sec = pkthdr->ts.tv_sec;
    ssl_connection.time.tv_usec = pkthdr->ts.tv_usec;
    ssl_connection.packets = 1;

    ssl_connection.size_in_B = 0;
    ssl_connection.client_ip = ip->src;
    ssl_connection.server_ip = ip->dst;
    ssl_connection.server_hello = false;

    return ssl_connection;
}

void finish(unsigned pos, struct timeval ts){

    if (buffer[pos].server_hello == true) {
        buffer[pos].duration = get_duration(buffer[pos].time,ts);//get_duration(buffer[pos].time, pkthdr->ts);
        print_conn(buffer[pos]);
        delete_item(pos);
    }
}

int append_item(Ssl_data* data){

    buffer_len += 1;

    if (!buffer[0].client_ip)
        buffer = malloc(sizeof(Ssl_data));
    else
        buffer = realloc(buffer, buffer_len * sizeof(Ssl_data));

    if (!buffer) {
        err_msg("Error while reallocating memory");
        return ERR_MEMORY;
    }

    buffer[buffer_len-1] = *data;

    return OK;
}

int find_item(unsigned short port){

    for (unsigned i = 0; i < buffer_len; i++) {
        if (port == buffer[i].client_port){
            return i;
        }
    }

    return NOT_FOUND;
}

int delete_item(int pos){

    Ssl_data* temp = malloc((buffer_len - 1) * sizeof(Ssl_data)); // allocate an array with a size 1 less than the current one
    if (temp == NULL) { err_msg(ERR_MEMORY,"ERR MEMORY");}

    if (pos != 0)
        memcpy(temp, buffer, pos * sizeof(Ssl_data)); // copy everything BEFORE the index

    if (pos != (buffer_len - 1))
        memcpy(temp + pos, buffer + pos + 1, (buffer_len - pos - 1) * sizeof(Ssl_data));// copy everything AFTER the index

    if (!buffer)
        free (buffer);

    buffer = temp;
    buffer_len--;

    return OK;
}

void increment_count(int pos, u_char* payload){
    int content_type = payload[CONTENT_B];

    buffer[pos].packets++;

     if ((payload[VERSION_B] == 0x03) && ((payload[VERSION_B+1] == 0x03) ||
          payload[VERSION_B+1] == 0x01)) { //sometimes theres no ssl head
         if (content_type == HANDSHAKE || content_type == APP_DATA ||
             content_type == CIPHER || content_type == ALERT) {
                buffer[pos].size_in_B += get_len(payload,SSL_LEN);
            }
     }
     else {
         fprintf(stderr,"Version not supported.");
     }
}



