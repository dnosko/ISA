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
        perror(errbuff);
        err_msg(ERR_FILE,"%s",errbuff);
    }

    struct pcap_pkthdr *header;
    const u_char *packet;

    int packetCount = 0;
    int i;

    //pcap_close(handler);
    return OK;
}

int analyse_interface_packets(char* interface) {

}
