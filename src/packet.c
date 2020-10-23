/*****************************************
 *              ISA 2020
 *        xnosko05 - Daša Nosková
 *        Monitoring SSL spojenia
 ****************************************/

#include "packet.h"

void get_port(const u_char *packet,struct tcphdr *tcph,unsigned short *src_port){

    *src_port = ntohs(tcph->source);
}

char* check_flag(struct tcphdr *tcph){
    // SYN SET AND ACK NOT
    if ((tcph->th_flags & TH_SYN) && !(tcph->th_flags & TH_ACK))
        return "SYN";
    // FIN AND ACK too, ending with client FIN or server fin??? zatial konci s klient fin
    if (tcph->th_flags & TH_FIN)
        return "FIN";

    return "";
}