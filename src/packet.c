/*****************************************
 *              ISA 2020
 *        xnosko05 - Daša Nosková
 *        Monitoring SSL spojenia
 ****************************************/

#include "packet.h"
#include "error.h"

unsigned short get_port(struct tcphdr *tcph,char* type){
    if (!strcmp("src",type))
        return ntohs(tcph->source);
    if (!strcmp("dst",type))
        return ntohs(tcph->dest);

    return ERR_FUN;
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

char* get_ip_addr(struct iphdr *iph, char* type) {

    struct sockaddr_in ip_addr;

    memset(&ip_addr, 0, sizeof(ip_addr));

    if (!strcmp(type,"src"))
        ip_addr.sin_addr.s_addr = iph->saddr;
    else if(!strcmp(type,"dst"))
        ip_addr.sin_addr.s_addr = iph->daddr;

    return inet_ntoa(ip_addr.sin_addr);
}

