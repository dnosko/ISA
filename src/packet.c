/*****************************************
 *              ISA 2020
 *        xnosko05 - Daša Nosková
 *        Monitoring SSL spojenia
 ****************************************/

#include "packet.h"
#include "error.h"


int get_tcphdr_size(const u_char* packet, unsigned iphdrlen){
    u_char* payload = (u_char *)(packet + ETHERNET_SIZE + iphdrlen);
    debug("tcpheader %02x ",payload[12]);
    //char decimal[2];
    //sprintf(decimal,"%d",payload[12]);
    //if (payload[12] == 0xa0) return 32;

    return payload[12];
}

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

void get_ip_addr(struct iphdr *iph, char *src, char *dst) {

    //inet_ntop(AF_INET6, (void*)(&iph->ip6_src), source_ip, INET6_ADDRSTRLEN)
    // pozri prednasky asi mozno tam bdue nejaky kod na ipv6
    //https://blog.apnic.net/2017/10/24/raw-sockets-ipv6/
    //https://www.winsocketdotnetworkprogramming.com/winsock2programming/winsock2advancedInternet3c.html
    struct sockaddr_in source, dest;

    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;

    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;

    strcpy(src, inet_ntoa(source.sin_addr));
    strcpy(dst, inet_ntoa(dest.sin_addr));

}

int get_len(u_char* payload, int position){
    long len = 0;
    char hex_str[7];
    debug("get_len 0x%02x%02x\n",payload[position], payload[position + 1]);
    sprintf(hex_str,"0x%02x%02x",payload[position], payload[position + 1]);
    len = strtol(hex_str, NULL, 16);
    debug("GET_LEN: %ld\n", len);
    return (int)len;
}

float get_duration(struct timeval start, struct timeval end){

    long milisec_start = start.tv_sec * MILLI + start.tv_usec;
    //debug("milliseconds_start %ld\n", milisec_start);
    long milisec_end = end.tv_sec * MILLI + end.tv_usec;
    //debug("milliseconds_end %ld\n", milisec_end);
    long milisec = milisec_end - milisec_start;
    //debug("seconds %ld\n",milisec );
    float sec_ = (float) milisec;
    //debug("float ??? %f\n",sec_);
    float sec = sec_/1000 ;
    //debug("float ok %f\n",sec);
    if (sec < 0)
        sec *= -1;
    return sec;
}

int get_ext_pos(u_char* payload){

    int cipher_len  = get_len(payload,CIPHER_LEN);
    debug("CIPHERLEN %d\n",cipher_len);
    int compr_pos = (CIPHER_LEN+1)+cipher_len;
    debug("compr_pos %d\n",compr_pos);
    int compr_len = payload[compr_pos+1];
    debug("compr_len %d\n",compr_len);
    int exts_start = compr_pos+compr_len+2; //extentions start at this B
    debug("extentions_start at %d\n",exts_start );
    int all_ext_len = get_len(payload,exts_start);
    debug("all_ext_len %d\n",all_ext_len );
    int ext_type_pos = exts_start +2;
    int ext_len_pos = ext_type_pos+2 ;
    int ext_len = get_len(payload,ext_len_pos);
    //TODO pridat ak extention SNI nie je

    while (!(payload[ext_type_pos] == 0x00 && payload[ext_type_pos+1] ==0x00)){
        //if (ext_len == 0){
        //    printf("not found");
        //    return -1;}
        ext_len = get_len(payload,ext_len_pos);
        debug("EXTENTION LEN: %d", ext_len_pos);
        ext_type_pos = ext_len+ext_len_pos+2;
        printf("extention len %d\n",ext_len);
        ///all_ext_len = all_ext_len - ext_len;
        ///printf("ext len total %d\n",all_ext_len);
    }

    return (ext_type_pos+SNI_EXT_OFFSET);
}