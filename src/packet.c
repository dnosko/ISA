/*****************************************
 *              ISA 2020
 *        xnosko05 - Daša Nosková
 *        Monitoring SSL spojenia
 ****************************************/

#include "packet.h"

unsigned short get_port(struct tcphdr *tcph,char* type){
    if (!strcmp("src",type))
        return ntohs(tcph->source);
    if (!strcmp("dst",type))
        return ntohs(tcph->dest);
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