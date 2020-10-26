/*****************************************
 *              ISA 2020
 *        xnosko05 - Daša Nosková
 *        Monitoring SSL spojenia
 ****************************************/

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

// spojenia ktore neboli ukoncene ak sigint tak vypisat "-"

static volatile int keepRunning = false;


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

    unsigned i,len;
    len = buffer_len;
    while(len != 0) {
        //printf("buffer_len %d\n",buffer_len);
        i = len -1;
        buffer[i].duration = (float) -1.0;
        // co je kurva na SNI ??????
        // printf("buffer port %s\n",buffer[i].SNI);
        /*if (buffer[i].server_hello){
            printf("NN\n");
            print_conn(buffer[i]);
            delete_item(buffer[i].client_port);
        }*/
        //printf("NN\n");
        delete_item(buffer[i].client_port);
        //free(&buffer[i]);
        len--;
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
        //pcap_close(handler);
        return ERR_PCAP;
    }
    if(pcap_setfilter(handler, &fp) == -1)
    {
        printf("\npcap_setfilter() failed\n");
        //pcap_close(handler);
        return ERR_PCAP;
    }

    return OK;
}
void process_packet(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet) {

    //	IP header -> X + SIZE_ETHERNET
    struct iphdr* iph = (struct iphdr*)(packet + ETHERNET_SIZE);
    unsigned short iphdrlen = iph->ihl*4;
    struct tcphdr* tcp = (struct tcphdr*)(packet + iphdrlen + ETHERNET_SIZE);
    u_char *payload; /* Packet payload */
    int tcpheader_size = get_tcphdr_size(packet,iphdrlen);

    payload = (u_char *)(packet + ETHERNET_SIZE + iphdrlen + tcpheader_size ); // this is ssl payload

    unsigned short src_port = get_port(tcp, "src"); // potrebujem obidva porty skontrolovat vzdy ten co nie je 443

    if (src_port != SSL_PORT){
        process_client(src_port,pkthdr,payload,iph,tcp);
    }
    else { // source je SSL
        process_server(tcp,payload,pkthdr);
    }
}

void process_client(unsigned short port,const struct pcap_pkthdr* pkthdr,u_char* payload,struct iphdr* iph,struct tcphdr* tcp){

    if (!strcmp(check_flag(tcp),"SYN")) { // add new connection to buffer
        Ssl_data ssl = init_item(port,pkthdr,iph,payload);
        //printf("debug %")
        append_item(&ssl);
    }
    else {
        increment_count(port,payload);
        //printf("port %d : payload content %02x %02x %02x \n",port, payload[CONTENT_B], payload[CONTENT_B+1], payload[CONTENT_B+2]);
        if((payload[CONTENT_B] == HANDSHAKE) && (payload[HANDSHAKE_B] == CLIENT_HELLO)) {
            add_sni(payload,port);
        }
    }
}

void process_server(struct tcphdr* tcp, u_char* payload,const struct pcap_pkthdr* pkthdr){
    unsigned short client_port = get_port(tcp, "dst");
    // get destination port, check if its in buffer ak nie tak zahod ak je tak:
    int pos = find_item(client_port);
    //printf("payload content %02x \n",payload[CONTENT_B]);
    if((payload[CONTENT_B] == HANDSHAKE) && (payload[HANDSHAKE_B] == SERVER_HELLO)) {
        printf("##############\n");
        buffer[pos].server_hello = true;
    }
    increment_count(client_port,payload);

    if (buffer[pos].server_hello == true && pos != -1) {
        if(strcmp(check_flag(tcp),"FIN")) return;
        debug("get_duration %f\n",get_duration(buffer[pos].time, pkthdr->ts));
        buffer[pos].duration = get_duration(buffer[pos].time, pkthdr->ts);//get_duration(buffer[pos].time, pkthdr->ts);
        debug("#### DELETE.%d: packets %d: duration %f",buffer[pos].client_port,buffer[pos].packets,buffer[pos].duration);
        print_conn(buffer[pos]);
        debug("hereee");
        delete_item(client_port);
    }
}

Ssl_data init_item(unsigned short client_port,const struct pcap_pkthdr* pkthdr,struct iphdr *iph, u_char* payload){

    Ssl_data ssl_connection;
    ssl_connection.client_port = client_port;
    ssl_connection.time.tv_sec = pkthdr->ts.tv_sec;
    ssl_connection.time.tv_usec = pkthdr->ts.tv_usec;
    ssl_connection.packets = 1;
    // get source and destination ip address
    char* src = (char*) malloc(sizeof(char)*iph->ihl*4);
    char *dst = (char*) malloc(sizeof(char)*iph->ihl*4);
    get_ip_addr(iph,src,dst);
    ssl_connection.size_in_B = get_len(payload,SSL_LEN);
    ssl_connection.client_ip = src;
    ssl_connection.server_ip = dst;

    return ssl_connection;
}


void add_sni(u_char *payload, unsigned short port){

    printf("halo\n");
    int pos = find_item(port);
    int ext_B = get_ext_pos(payload);
    printf("EX_B %d \n",ext_B);
    int len = (int)get_len(payload,ext_B);
    char* sni = extract_data(payload,ext_B,len+1);
    if (pos != -1) {
        //if (sni[0] == '\0') buffer[pos].SNI = "NO SNI"; // kontrola verzie, lebo niekedy su na inej pozicii SNI
        buffer[pos].SNI = sni;
        debug("SNI %s\n",sni);
    }
}

int append_item(Ssl_data* data){
    debug("buffer_len %i",buffer_len);
    buffer_len += 1;
    //debug("klient ip %s \n", buffer[buffer_len-1].client_ip);
    buffer = realloc(buffer, buffer_len * sizeof(Ssl_data));
    if (!buffer) {
        err_msg(ERR_MEMORY,"Error while reallocating memory");
    }

    buffer[buffer_len-1] = *data;
    debug("item added buffer_len %d added port %d time %lu",buffer_len,buffer[buffer_len-1].client_port,
            (buffer[buffer_len-1].time.tv_sec*MILLI + buffer[buffer_len-1].time.tv_usec));
   // debug("klinet ip %s \n", buffer[buffer_len-1].client_ip);
    return OK;
}

int find_item(unsigned short port){
    debug("buffer_len %d looking for %d",buffer_len, port);
    for (unsigned i = 0; i < buffer_len; i++) {
        debug("i: %d buffer port %d",i, buffer[i].client_port);
        if (port == buffer[i].client_port){
            return i;
        }
    }
    debug("didnt find port %d",port);
    return -1;
}

int delete_item(unsigned short port){
    debug("deleting.. %d buffer_len %d",port,buffer_len);
    int position = find_item(port);
    debug("position %d",position);
    if (position != -1) {
        Ssl_data* temp = malloc((buffer_len - 1) * sizeof(Ssl_data)); // allocate an array with a size 1 less than the current one
        if (temp == NULL) { return ERR_MEMORY;}

        if (position != 0)
            memcpy(temp, buffer, position * sizeof(Ssl_data)); // copy everything BEFORE the index

        if (position != (buffer_len - 1))
            memcpy(temp+position, buffer+position+1, (buffer_len - position - 1) * sizeof(Ssl_data));// copy everything AFTER the index

        debug("delete item free %d buffer_len",buffer_len);
        free (buffer);
        buffer = temp;
        buffer_len--;
    }
    return OK;
}

void increment_count(unsigned short port, u_char* payload){
    int content_type = payload[CONTENT_B];
    int pos = find_item(port);
    debug("port %d on pos %d",port,pos);
    if (pos != -1) { //port is in buffer
        buffer[pos].packets++;
        debug("A: %d: %d",buffer[pos].client_port, buffer[pos].packets);
        //if (payload[0] != 0){ //sometimes theres no ssl head
            if (content_type == HANDSHAKE || content_type == APP_DATA) {
                buffer[pos].size_in_B += get_len(payload,SSL_LEN);
            }
        //}
    }
    debug("hm");
}


