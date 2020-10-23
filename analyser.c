/*****************************************
 *              ISA 2020
 *        xnosko05 - Daša Nosková
 *        Monitoring SSL spojenia
 ****************************************/

#include <zconf.h>
#include <openssl/ssl.h>
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
 *                 d) tcp packet -> ak client posle FIN (0x011) tak koniec
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

    struct pcap_pkthdr *header;
    const u_char *packet;

    while (pcap_next_ex(handler,&header,&packet) >= 0) {
        debug("header secs: %lu", header->ts.tv_usec);
        //debug("packet %c", packet);
    }

    return OK;
}

int analyse_interface_packets(pcap_t* handler,bpf_u_int32 pNet) {


    if (set_filter(handler,pNet) == ERR_PCAP){
        return ERR_PCAP;
    }

    int infinite_loop = -1;
    int return_code;

    return_code = pcap_loop(handler,infinite_loop, process_packet, NULL);
    if (return_code == PCAP_ERROR || return_code == PCAP_ERROR_BREAK ) {
        debug("here");
        //pcap_close(handler);
        return return_code;
    }

    //pcap_close(handler); //close session
    return OK;
}

int set_filter(pcap_t* handler,bpf_u_int32 netmask) {
    struct bpf_program fp;        /* to hold compiled program */

    // apply ssl filter
    if(pcap_compile(handler, &fp,SSL_FILTER, 0, netmask) == -1)
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

    Ssl_data ssl_connection;

    //	IP header -> X + SIZE_ETHERNET
    struct iphdr *iph = (struct iphdr*)(packet + ETHERNET_SIZE);
    unsigned short iphdrlen = iph->ihl*4;
    struct tcphdr *tcp=(struct tcphdr*)(packet + iphdrlen + ETHERNET_SIZE);

    // get port number
    unsigned short *src_port = (unsigned short *) malloc(sizeof(unsigned short));
    get_port(packet,tcp, src_port);

    // check if port is already in use
    find_item(*src_port,&ssl_connection);
    // port isn't in the buffer
    if (&(ssl_connection) == NULL) {
        // check if flag is SYN
        ssl_connection.client_port = *src_port;
        ssl_connection.time = localtime((const time_t *) &pkthdr->ts);
        append_item(ssl_connection);
    }
    else { // port is in buffer already

    }


    //printf("%d-%2d-%2d\n%2d:%2d:%2d.%ld", time->tm_year, time->tm_mon, time->tm_mday, time->tm_hour, time->tm_min,
    //                                             time->tm_sec,pkthdr->ts.tv_usec);

    free(src_port);
}

int append_item(Ssl_data data){
    buffer_len++;
    debug("buffer_len %i",buffer_len);
    buffer = realloc(buffer, buffer_len * sizeof(Ssl_data));
    if (!buffer) {
        err_msg(ERR_MEMORY,"Error while reallocating memory");
    }

    buffer[buffer_len-1] = data;
    return OK;
}

void find_item(unsigned short port, Ssl_data* item){
    for (unsigned i = 0; i < buffer_len; i++) {
        Ssl_data data = buffer[i];
        if (port == data.client_port){
            item = &data;
            return;
        }
    }
    item = NULL;
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

