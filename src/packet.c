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

/******************************FORMAT******************************************************/
void convert_ascii(char *ascii_str, unsigned int val) {
    char ascii_val[32] = "";
    unsigned int decimal = val; //decimal
    if (32 <= decimal && decimal < 127) { //printable chars
        sprintf(ascii_val,"%c",val);
        printf("ascii_val %s   ",ascii_val);
        printf("val %c   ",val);
        strcat(ascii_str,ascii_val);
        printf("ascii_str %s   ",ascii_str);
    }
    else { // non printable ascii, end of sni
        return;
    }
}

void print_packet(const u_char* packet, unsigned X, int no_bytes) {

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

char* extract_data(const u_char* packet, unsigned from_B, unsigned to_B, int no_bytes) {
    char* ascii_str = (char*) malloc(sizeof(char)*(to_B-from_B+1));
    //unsigned Y = (X != 0) ? X*16 : 0; // print 0-15, 16-32, 32 - 64 ... B
    int Bytes = to_B-from_B;
    for (unsigned i = from_B; i <= to_B; i++) {
        if (Bytes != 0) {
            //printf("%02X ", (unsigned int) packet[i]);
            convert_ascii(ascii_str, (unsigned int) packet[i]);
            printf("byte: %d: %s\n",no_bytes,ascii_str);
            Bytes--;
        }
        else //if all packet has been printed, print spaces
            printf("   ");
    }
    printf("%s\n",ascii_str);
    return ascii_str;
}
