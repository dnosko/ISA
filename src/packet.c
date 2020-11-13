/*****************************************
 *              ISA 2020
 *        xnosko05 - Daša Nosková
 *        Monitoring SSL spojenia
 ****************************************/

#include "packet.h"
#include "error.h"
#include <netinet/in.h>


int get_ip_version(const u_char * packet){

    int version = (packet + ETHERNET_SIZE)[VERSION];

    return (version == IPV4) ? 4 : 6;
}

int get_tcphdr_size(const u_char* packet, unsigned iphdrlen){
    u_char* payload = (u_char *)(packet + ETHERNET_SIZE + iphdrlen);


    if (payload[12] == 0x80) return 32; // when its set to 0x80 header is 32

    return MIN_TCPHDR;
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

    if ((tcph->syn) && !(tcph->ack))
        return "SYN";
    // FIN AND ACK too, ending with client FIN or server fin??? zatial konci s klient fin
    if (tcph->fin)
        return "FIN";

    return "";
}

void get_ip_addr(struct iphdr *iph, char *src, char *dst, int version) {

    struct sockaddr_in source, dest;

    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;

    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;

    strcpy(src, inet_ntoa(source.sin_addr));
    strcpy(dst, inet_ntoa(dest.sin_addr));
}


void get_ipv6_addr(struct ip6_hdr *iphdr, char *src, char *dst){

    char buf[INET6_ADDRSTRLEN];

    inet_ntop(AF_INET6, &(iphdr->ip6_src), buf, sizeof(buf));
    strcpy(src, buf);
    inet_ntop(AF_INET6, &(iphdr->ip6_dst), buf, sizeof(buf));
    strcpy(dst, buf);
}

int get_len(u_char* payload, int position){
    long len = 0;
    char hex_str[7];

    sprintf(hex_str,"0x%02x%02x",payload[position], payload[position + 1]);
    len = strtol(hex_str, NULL, 16);

    return (int) len;
}

float get_duration(struct timeval start, struct timeval end){

    long sec = end.tv_sec - start.tv_sec;
    long usec = end.tv_usec - start.tv_usec;
    float usec_f = (float) usec;
    usec_f = usec_f/MICRO;
    float sum = sec + usec_f;

    return sum;
}

int get_ext_pos(u_char* payload){


    int cipher_len,compr_pos,compr_len,exts_start,ext_type_pos,ext_len_pos,ext_len;
    int count = 0;// max  loops, SNi is always first or second extension

    cipher_len  = get_len(payload,CIPHER_LEN);

    compr_pos = (CIPHER_LEN+1)+cipher_len;

    compr_len = payload[compr_pos+1];

    exts_start = compr_pos+compr_len+2; //extentions start at this B

    ext_type_pos = exts_start +2;
    ext_len_pos = ext_type_pos+2 ;

    while (!(payload[ext_type_pos] == SNI_TYPE && payload[ext_type_pos+1] == SNI_TYPE)){
        ext_len = get_len(payload,ext_len_pos);
        ext_type_pos = ext_len+ext_len_pos+2;
        count++;
        if (count == 2) return -1;
    }

    return (ext_type_pos+SNI_EXT_OFFSET);
}


void add_sni(u_char* payload, int pos, Ssl_data* buffer){

    char* sni;
    int ext_B = get_ext_pos(payload); // get Bth where SNI extension starts

    if (ext_B != -1) {
        int len = (int)get_len(payload,ext_B); // get length of SNI
        sni = get_SNI(payload, ext_B,len+1); //extract SNI name
        buffer[pos].SNI = sni;
    }
    else {
        buffer[pos].SNI = "";
    }
}

char* get_SNI(const u_char* packet, unsigned from_B, unsigned len) {

    char* ascii_str;
    int pos;
    char ret_val;
    unsigned end_sni;

    ascii_str = (char*) malloc(sizeof(char)*len+1);
    pos = 0;
    end_sni = from_B+len;

    for(unsigned i = from_B; i < end_sni; i++) {
        ret_val = convert_ascii((unsigned int) packet[i]);
        if (ret_val != '\0')
            ascii_str[pos] = ret_val;
        else
            ascii_str[pos] = '\0';
        pos++;
    }
    ascii_str[len] = '\0';
    return ascii_str;
}

void print_conn(Ssl_data data){

    // convert time
    struct tm* lt = localtime(&data.time.tv_sec);
    char time[MAX_TIME];
    // yyyy-mm-dd hh:mm:ss.usec
    strftime(time, MAX_TIME-1, "%Y-%m-%d %X", lt);

    printf("%s.%06ld,", time,data.time.tv_usec); // time
    printf("%s,%d,%s,%s,",data.client_ip,data.client_port,data.server_ip,data.SNI); //ip addresses
    printf("%lu,%d,%f\n",data.size_in_B,data.packets,data.duration);
}

char convert_ascii(unsigned int val) {
    char ascii_val[2];
    unsigned int decimal = val; //decimal
    if ((32 <= decimal && decimal < 127)) { //printable chars
        sprintf(ascii_val,"%c",val);
        return ascii_val[0];
    }
    return '\0'; //non printable ascii
}