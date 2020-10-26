/*****************************************
 *              ISA 2020
 *        xnosko05 - Daša Nosková
 *        Monitoring SSL spojenia
 ****************************************/

#include <time.h>
#include "format.h"

char convert_ascii(unsigned int val) {
    char ascii_val[2];
    unsigned int decimal = val; //decimal
    if ((32 <= decimal && decimal < 127)) { //printable chars
        sprintf(ascii_val,"%c",val);
        return ascii_val[0];
    }
    return '\0'; //non printable ascii
}
