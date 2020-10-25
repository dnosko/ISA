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

    //inet_ntop(AF_INET6, (void*)(&iph->ip6_src), source_ip, INET6_ADDRSTRLEN)
    // pozri prednasky asi mozno tam bdue nejaky kod na ipv6
    //https://blog.apnic.net/2017/10/24/raw-sockets-ipv6/
    //https://www.winsocketdotnetworkprogramming.com/winsock2programming/winsock2advancedInternet3c.html

    if (!strcmp(type,"src"))
        ip_addr.sin_addr.s_addr = iph->saddr;
    else if(!strcmp(type,"dst"))
        ip_addr.sin_addr.s_addr = iph->daddr;

    return inet_ntoa(ip_addr.sin_addr);
}

long get_len(u_char* payload, int position){
    long len = 0;
    char hex_str[7];
    //printf("get_len 0x%02x%02x\n",payload[position], payload[position + 1]);
    sprintf(hex_str,"0x%02x%02x",payload[position], payload[position + 1]);
    len = strtol(hex_str, NULL, 16);
    debug("GET_LEN: %ld\n", len);
    return len;
}

float get_duration(struct timeval start, struct timeval end){

    long milisec_start = start.tv_sec * MILLI + start.tv_usec;
    debug("milliseconds_start %ld\n", milisec_start);
    long milisec_end = end.tv_sec * MILLI + end.tv_usec;
    debug("milliseconds_end %ld\n", milisec_end);
    long milisec = milisec_end - milisec_start;
    debug("seconds %ld\n",milisec );
    float sec_ = (float) milisec;
    debug("float ??? %f\n",sec_);
    float sec = sec_/1000 ;
    debug("float ok %f\n",sec);
    if (sec < 0)
        sec *= -1;
    return sec;
}