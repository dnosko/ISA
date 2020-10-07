/*****************************************
 *              ISA 2020
 *        xnosko05 - Daša Nosková
 *        Monitoring SSL spojenia
 ****************************************/

#include "analyser.h"
#include <pcap/pcap.h>


int analyse_file_packets(char* pcap_file){

    char errbuff[PCAP_ERRBUF_SIZE];

    //open file
    pcap_t * handler = pcap_open_offline(pcap_file, errbuff);

    if (handler == NULL) {
        pcap_perror(handler,errbuff);
        err_msg(ERR_FILE,"");
    }

    struct pcap_pkthdr *header;
    const u_char *packet;

    while (pcap_next_ex(handler,&header,&packet) >= 0) {
        debug("header secs: %lu", header->ts.tv_usec);
        //debug("packet %c", packet);
    }
    //pcap_loop(handler, 10, process_packet, NULL);



    pcap_close(handler);
    return OK;
}

int analyse_interface_packets(char* interface) {

}

void process_packet(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet) {
    debug("header secs: %lu", pkthdr->ts.tv_usec);
    //	IP header -> X + SIZE_ETHERNET

}

