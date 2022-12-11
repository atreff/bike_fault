#include <stdlib.h> // malloc, free
#include <stdint.h>
#include <stdio.h> // FILE, fopen, fwrite, fclose
#include <string.h> // strlen

#include "internal/bike_defs.h" // R_BYTES, M_BYTES
#include "export.h"
#include "util.h" //bin2hex

void export_keys_aws(const char *filename, uint8_t *sk, uint8_t *pk) {
    FILE *f = fopen(filename, "w");
    const char *header = "# BIKE\n\ncount = 0\nseed = *\n";
    fwrite(header, strlen(header), 1, f);
    const char *text_pk = "pk = ";
    char *pk_hex = malloc(2 * R_BYTES + 1);
    bin2hex(pk, pk_hex, R_BYTES);
    fwrite(text_pk, strlen(text_pk), 1, f);
    free(pk_hex);
    fwrite(pk_hex, strlen(pk_hex), 1, f);
    fwrite("\n", 1, 1, f);
    const char *text_sk = "sk = ";
    char *sk_hex = malloc(2 * ( 2 * R_BYTES) + 1);
    // We do not save corresponding weight lists, just fill with *!
    bin2hex(sk + WLIST_LEN, sk_hex, 2*R_BYTES);
    fwrite(text_sk, strlen(text_sk), 1, f);
    for (unsigned int ctr = 0; ctr < WLIST_LEN*2; ++ctr) {
        fwrite("*", 1, 1, f);
    }
    fwrite(sk_hex, strlen(sk_hex), 1, f);
    free(sk_hex);
    // We do not save the public key (again), just fill with #!
    for (unsigned int ctr = 0; ctr < R_BYTES * 2; ++ctr) {
        fwrite("#", 1, 1, f);
    }
    // We do not save the corresponding sigma, just fill with -!
    for (unsigned int ctr = 0; ctr < M_BYTES * 2; ++ctr) {
        fwrite("-", 1, 1, f);
    }
    fwrite("\n", 1, 1, f);
    const char *text_ct = "ct = *\n";
    fwrite(text_ct, strlen(text_ct), 1, f);
    const char *text_ss = "ss = *\n";
    fwrite(text_ss, strlen(text_ss), 1, f);
    fclose(f);
}
