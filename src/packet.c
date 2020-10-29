/*****************************************
 *              ISA 2020
 *        xnosko05 - Daša Nosková
 *        Monitoring SSL spojenia
 ****************************************/

#include "packet.h"
#include "error.h"


int get_ip_version(u_char * packet){

    int version = (packet + ETHERNET_SIZE)[VERSION];

    return (version == IPV4) ? 4 : 6;
}

int get_tcphdr_size(const u_char* packet, unsigned iphdrlen){
    u_char* payload = (u_char *)(packet + ETHERNET_SIZE + iphdrlen);
    debug("tcpheader %02x ",payload[12]);
    //podla options v tcp packete spracovat jeden za druhym asi

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
    printf("%d\n",iph->version);

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
    return (int) len;
}

//TODO UPRAVIT
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
    return sec/MILLI;
}

// TODO upravit
int get_ext_pos(u_char* payload){


    int cipher_len,compr_pos,compr_len,exts_start,ext_type_pos,ext_len_pos,ext_len;
    int count = 0;// max  loops, SNi is always first or second extention

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
    int ext_B = get_ext_pos(payload); // get Bth where SNI extention starts

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
    ret_val = 0;

    for(unsigned i = from_B; i < end_sni; i++) {
        //debug"packet %02X\n", (unsigned int) packet[i]);
        ret_val = convert_ascii((unsigned int) packet[i]);
        if (ret_val != '\0')
            ascii_str[pos] = ret_val;
        else
            ascii_str[pos] = '\0';
        pos++;
    }
    ascii_str[len] = '\0';
    debug("get_SNI %s len: %d pos: %d\n",ascii_str,len,pos);
    return ascii_str;
}