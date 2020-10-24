/*****************************************
 *              ISA 2020
 *        xnosko05 - Daša Nosková
 *        Monitoring SSL spojenia
 ****************************************/

#include "analyser.h"

// SSL vzdy port 443
// verziu ssl urcuje server
//TODO <timestamp>,<client ip><client port>,<server ip><SNI>,<bytes>,<packets>,<duration sec>
// filtrovat vsetky tcp packety. Pride packet. Pozriem ci sa cislo portu nachadza v mojom strome
/* A) nenachadza sa: pozriem flag tcp packetu ak SYN(0x002) -> uloz cislo portu a pocet=0 a cas do bufferu/stromu */
/* B) nachadza sa:  pricitaj paket++,skontrolovat ci to je:
 *                  a)ssl client hello - zobrat info do struktury
 *                  b)ssl server hello - kontrola ci je verzia podporovana
 *                                      - nastavit bool ze ok
 *                  c)packet so ssl, pricitaj dlzku (v hlavicke length),
 *                 d) tcp packet -> ak server posle FIN (0x011) tak koniec
 *                               -> inak zahod packet a zober dalsi*/

// spojenia ktore neboli ukoncene ak sigint tak vypisat "-"

static volatile int keepRunning = false;

int no_bytes;

void intHandler(int dummy) {
    keepRunning = true;
}

int open_handler(char* interface, char* pcap_file) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handler;
    int return_code;

    //signal(SIGINT, intHandler);

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

    debug("hi");
    //	IP header -> X + SIZE_ETHERNET
    struct iphdr *iph = (struct iphdr*)(packet + ETHERNET_SIZE);
    unsigned short iphdrlen = iph->ihl*4;
    struct tcphdr *tcp = (struct tcphdr*)(packet + iphdrlen + ETHERNET_SIZE);

    unsigned short src_port = get_port(tcp, "src"); // potrebujem obidva porty skontrolovat vzdy ten co nie je 443
    if (src_port != SSL_PORT){
        if (!strcmp(check_flag(tcp),"SYN")) { // add new connection to buffer
            init_item(src_port,pkthdr,iph);
            debug("hoo");
        }
        else {
            increment_count(src_port);
        }
    }
    else { // source je SSL
        unsigned short client_port = get_port(tcp, "dst");
        debug("clientport %d soucerport %d",client_port, src_port);
        // get destination port, check if its in buffer ak nie tak zahod ak je tak:
        int pos = find_item(client_port);
        debug("ho");
        increment_count(client_port);
        debug("yo");
        if (!strcmp(check_flag(tcp),"FIN") && pos != -1) {
            //vypocitat duration, vypisat a zmazat z bufferu
            buffer[pos].duration = pkthdr->ts.tv_sec - buffer[pos].time->tv_sec;
            debug("#### DELETE.%d: packets %d: duration %lu",buffer[pos].client_port,buffer[pos].packets,buffer[pos].duration);
            print_conn(buffer[pos]);
            delete_item(client_port);
        }
    }
}

void init_item(unsigned short client_port,const struct pcap_pkthdr* pkthdr,struct iphdr *iph){

    Ssl_data ssl_connection;
    debug("adding port %i to buffer",client_port);
    ssl_connection.client_port = client_port;
    ssl_connection.time->tv_sec = pkthdr->ts.tv_sec;
    ssl_connection.time->tv_usec = pkthdr->ts.tv_usec;
    debug("time %lu",ssl_connection.time->tv_sec);
    ssl_connection.packets = 1;
    // get source and destination ip address
    ssl_connection.client_ip = get_ip_addr(iph,"src");
    ssl_connection.server_ip = get_ip_addr(iph,"dst");
    append_item(&ssl_connection);
    debug("hoho");
}

int append_item(Ssl_data* data){
    debug("buffer_len %i",buffer_len);
    buffer_len += 1;
    buffer = realloc(buffer, buffer_len * sizeof(Ssl_data));
    if (!buffer) {
        err_msg(ERR_MEMORY,"Error while reallocating memory");
    }

    buffer[buffer_len-1] = *data;
    debug("item added buffer_len %d added port %d",buffer_len,buffer[buffer_len-1].client_port);
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

void increment_count(unsigned short port){
    int pos = find_item(port);
    debug("port %d on pos %d",port,pos);
    if (pos != -1) { //port is in buffer
        buffer[pos].packets++;
        debug("A: %d: %d",buffer[pos].client_port, buffer[pos].packets);
        //TODO increment bytes zo ssl hlavicky
    }
}

void print_conn(Ssl_data data){

    // convert time
    struct tm* lt = localtime(&data.time->tv_sec);
    char time[MAX_TIME];
    // yyyy-mm-dd hh:mm:ss.usec
    strftime(time, MAX_TIME-1, "%Y-%m-%d %X", lt);

    printf("%s.%ld\n", time,data.time->tv_usec);
}

void convert_ascii(char *ascii_str, unsigned int val) {
    char ascii_val[16] = "";
    unsigned int decimal = val; //decimal
    if (32 <= decimal && decimal < 127) { //printable chars
        sprintf(ascii_val,"%c",val);
        strcat(ascii_str,ascii_val);
    }
    else { // non-printable values are replaced by a dot
        strcat(ascii_str,".");
    }
}

void print_packet(const u_char* packet, unsigned X) {

    printf("0x%.3d0: ",X);
    char ascii_str[16] = "";
    unsigned Y = (X != 0) ? X*16 : 0; // print 0-15, 16-32, 32 - 64 ... B
    for (unsigned i = Y; i < 16*(X+1); i++) {
        if (no_bytes != 0) {
            printf("%02X ", (unsigned int) packet[i]);
            convert_ascii(ascii_str, (unsigned int) packet[i]);
            no_bytes--;
        }
        else //if all packet has been printed, print spaces
            printf("   ");
    }
    printf("%s\n",ascii_str);
}

char* extract_data(const u_char* packet, unsigned from_B, unsigned to_B) {
    char *ascii_str = malloc(to_B-from_B+1);
    //unsigned Y = (X != 0) ? X*16 : 0; // print 0-15, 16-32, 32 - 64 ... B
    for (unsigned i = from_B; i <= to_B; i++) {
        if (no_bytes != 0) {
            //printf("%02X ", (unsigned int) packet[i]);
            convert_ascii(ascii_str, (unsigned int) packet[i]);
            no_bytes--;
        }
        else //if all packet has been printed, print spaces
            printf("   ");
    }
    //printf("%s\n",ascii_str);
    return ascii_str;
}


