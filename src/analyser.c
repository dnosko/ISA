/*****************************************
 *              ISA 2020
 *        xnosko05 - Daša Nosková
 *        Monitoring SSL spojenia
 ****************************************/

#include <netinet/ip6.h>
#include "analyser.h"

/* DOKUMENTACIA spojenie ukoncuje posledny TCp packet, po FIN od serveru
 *
 * */
// SSL vzdy port 443
// verziu ssl urcuje server
//TODO <timestamp>,<client ip>,<client port>,<server ip>,<SNI>,<bytes>,<packets>,<duration sec>
/*TODO
 * IPV6
 * KONTROLA VERZII -> ak nie je podporovana tak vypisat ze nie je podporovana na stderr a skip, 1.3 skip
 * VYPISAT NEUKONCENE SPOJENIA ALE IBA AK PRISIEL SERVER_HELLO TAKZE KONTROLA SERVE-hELLO
 * KONTROLA CI DANE ROZHRANIE EXISTUJE
 * daj init, delete etc do ineho suboru, plus algoritmus na sorting popr bin strom
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
            err_msg(ERR_PCAP, "Error: %s", errbuf);
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
        debug("here");
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
    struct tcphdr* tcp;
    u_char *payload; /* Packet payload */
    int tcpheader_size;
    unsigned short src_port;
    int ip_version;

    ip_version = get_ip_version(packet);

    if (ip_version == 6) { //ipv6
        ip6_hdr = (struct ip6_hdr *)(packet + ETHERNET_SIZE);
        iphdrlen = IPv6_HDR;
    }
    else { // ipv4
        iph = (struct iphdr*)(packet + ETHERNET_SIZE);
        iphdrlen = iph->ihl*4;
    }

    tcp = (struct tcphdr*)(packet + iphdrlen + ETHERNET_SIZE);
    tcpheader_size = get_tcphdr_size(packet,iphdrlen);

    payload = (u_char *)(packet + ETHERNET_SIZE + iphdrlen + tcpheader_size ); // this is ssl payload

    src_port = get_port(tcp, "src");

    if (src_port != SSL_PORT){
        process_client(src_port,pkthdr,payload,iph,tcp);
    }
    else { // source is SSL
        process_server(tcp,payload,pkthdr);
    }
}
/*SKUSIT TOTO VSETKO PREKOPIROVAT DO SUBORU */
void process_client(unsigned short port,const struct pcap_pkthdr* pkthdr,u_char* payload,struct iphdr* iph,struct tcphdr* tcp){

    if (!strcmp(check_flag(tcp),"SYN")) { // add new connection to buffer
        Ssl_data ssl = init_item(port, pkthdr, iph);
        append_item(&ssl);
    }
    else {
        int pos = find_item(port);

        if (pos == NOT_FOUND) return;

        if((payload[CONTENT_B] == HANDSHAKE) && (payload[HANDSHAKE_B] == CLIENT_HELLO)) {
            buffer[pos].server_hello = true;
            add_sni(payload,pos,buffer);
        }

        increment_count(pos,payload);
    }
}

void process_server(struct tcphdr* tcp, u_char* payload,const struct pcap_pkthdr* pkthdr){
    unsigned short client_port;
    int pos;

    client_port = get_port(tcp, "dst");

    pos = find_item(client_port);
    if (pos == NOT_FOUND) return;

    if((payload[CONTENT_B] == HANDSHAKE) && (payload[HANDSHAKE_B] == SERVER_HELLO)) {
        buffer[pos].server_hello = true;
    }

    increment_count(pos,payload);

    if (buffer[pos].server_hello == true) {
        if(strcmp(check_flag(tcp),"FIN") != 0) return;
        debug("get_duration %f\n",get_duration(buffer[pos].time, pkthdr->ts));
        buffer[pos].duration = get_duration(buffer[pos].time, pkthdr->ts);//get_duration(buffer[pos].time, pkthdr->ts);
        debug("#### DELETE.%d: packets %d: duration %f",buffer[pos].client_port,buffer[pos].packets,buffer[pos].duration);
        print_conn(buffer[pos]);
        delete_item(pos);
    }
}

Ssl_data init_item(unsigned short client_port, const struct pcap_pkthdr *pkthdr, struct iphdr *iph) {

    Ssl_data ssl_connection;
    ssl_connection.client_port = client_port;
    ssl_connection.time.tv_sec = pkthdr->ts.tv_sec;
    ssl_connection.time.tv_usec = pkthdr->ts.tv_usec;
    ssl_connection.packets = 1;
    // get source and destination ip address
    char* src = (char*) malloc(sizeof(char)*iph->ihl*4);
    char *dst = (char*) malloc(sizeof(char)*iph->ihl*4);
    get_ip_addr(iph,src,dst);
    ssl_connection.size_in_B = 0;
    ssl_connection.client_ip = src;
    ssl_connection.server_ip = dst;

    return ssl_connection;
}


int append_item(Ssl_data* data){
    debug("buffer_len %i",buffer_len);
    buffer_len += 1;

    if (!buffer[0].client_ip)
        buffer = malloc(sizeof(Ssl_data));
    else
        buffer = realloc(buffer, buffer_len * sizeof(Ssl_data));

    if (!buffer) {
        err_msg(ERR_MEMORY,"Error while reallocating memory");
    }

    buffer[buffer_len-1] = *data;
    debug("item added buffer_len %d added port %d time %lu",buffer_len,buffer[buffer_len-1].client_port,
            (buffer[buffer_len-1].time.tv_sec*MILLI + buffer[buffer_len-1].time.tv_usec));

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
    debug("deleting.. %d buffer_len %d", pos, buffer_len);

    Ssl_data* temp = malloc((buffer_len - 1) * sizeof(Ssl_data)); // allocate an array with a size 1 less than the current one
    if (temp == NULL) { err_msg(ERR_MEMORY,"ERR MEMORY");}

    if (pos != 0)
        memcpy(temp, buffer, pos * sizeof(Ssl_data)); // copy everything BEFORE the index

    if (pos != (buffer_len - 1))
        memcpy(temp + pos, buffer + pos + 1, (buffer_len - pos - 1) * sizeof(Ssl_data));// copy everything AFTER the index
        debug("delete item free %d buffer_len",buffer_len);
    if (!buffer)
        free (buffer);

    buffer = temp;
    buffer_len--;

    return OK;
}

void increment_count(int pos, u_char* payload){
    int content_type = payload[CONTENT_B];
    debug("port %d on pos %d", pos, pos);

    buffer[pos].packets++;
        //if (buffer[pos].packets >= 4 && buffer[pos].client_hello != true)
        //    {printf("NO SERVER_HELLO DELETE %d\n",port);delete_item(port);}
        //debug("A: %d:%02x",buffer[pos].client_port,content_type);

     if ((payload[VERSION_B] == 0x03) && ((payload[VERSION_B+1] == 0x03) ||
          payload[VERSION_B+1] == 0x01)) { //sometimes theres no ssl head
         if (content_type == HANDSHAKE || content_type == APP_DATA ||
             content_type == CIPHER || content_type == ALERT) {
                //debug("getlen inc %d\n",get_len(payload,SSL_LEN));
                buffer[pos].size_in_B += get_len(payload,SSL_LEN);
            }
     }
}

void print_conn(Ssl_data data){

    // convert time
    struct tm* lt = localtime(&data.time.tv_sec);
    char time[MAX_TIME];
    // yyyy-mm-dd hh:mm:ss.usec
    strftime(time, MAX_TIME-1, "%Y-%m-%d %X", lt);

    printf("%s.%lu,", time,data.time.tv_usec); // time
    printf("%s,%d,%s,%s,",data.client_ip,data.client_port,data.server_ip,data.SNI); //ip addresses
    if (data.duration == -1) printf("%lu,%d,%c\n",data.size_in_B,data.packets,'-');
    else printf("%lu,%d,%f\n",data.size_in_B,data.packets,data.duration);
}


