#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include "util.h"

void print_help() {
    printf(
        "BIKE Tool\n"
        "Possible arguments:\n"
        "\t-h/--help\t\tprints this help.\n"
        "\t-v/--verbose\t\tverbose output.\n"
        "\t-i/--iterations=ITER\tsets number of iterations.\n");
}

void hex2bin(const char *in, uint8_t *out, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        sscanf(&in[2*i], "%2hhx", &out[i]);
    }
}

void bin2hex(const uint8_t *in, char *out, size_t len) {
    static const char HEX[] = "0123456789ABCDEF";
    for (size_t i = 0; i < len; ++i) {
        out[i*2]   = HEX[in[i] >> 4];
		out[i*2+1] = HEX[in[i] & 0x0F];
    }
    out[2*len] = '\0';
}
