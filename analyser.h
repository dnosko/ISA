/*****************************************
 *              ISA 2020
 *        xnosko05 - Daša Nosková
 *        Monitoring SSL spojenia
 ****************************************/

#ifndef ISA_ANALYSER_H
#define ISA_ANALYSER_H

#include <bits/types/FILE.h>
#include "error.h"
#include <pcap/pcap.h>

int analyse_interface_packets();
int analyse_file_packets(char* pcap_file);

#endif //ISA_ANALYSER_H
