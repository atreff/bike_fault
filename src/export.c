#include <stdlib.h> // malloc, free
#include <stdint.h> // uint8_t
#include <stdio.h> // FILE, fopen, fwrite, fclose
#include <string.h> // strlen

#include "internal/bike_defs.h" // R_BYTES, M_BYTES, D
#include "export.h"
#include "util.h" //bin2hex

void export_keys_aws(const char *filename, uint8_t *sk, uint8_t *pk, uint8_t *sigma, uint8_t *seed) {
    const char *header = "# BIKE\n\ncount = 0\nseed = ";
    const char *text_pk = "pk = ";
    const char *text_sk = "sk = ";
    const char *text_ct = "ct = *\n";
    const char *text_ss = "ss = *\n";

    char *seed_hex = malloc(2 * 48 + 1);
    char *pk_hex = malloc(2 * R_BYTES + 1);
    char *sk_hex = malloc(2 * (2 * R_BYTES) + 1);
    char *wlist_hex = malloc(2 * (2 * D) + 1);
    char *sigma_hex = malloc(2 * M_BYTES + 1);

    bin2hex(seed, seed_hex, 48);
    bin2hex(pk, pk_hex, R_BYTES);
    bin2hex(sk + WLIST_LEN, sk_hex, 2 * R_BYTES);
    bin2hex(sk, wlist_hex, WLIST_LEN);
    bin2hex(sigma, sigma_hex, M_BYTES);

    FILE *f = fopen(filename, "w");
    fwrite(header, strlen(header), 1, f);
    fwrite(seed_hex, strlen(seed_hex), 1, f);
    fwrite("\n", 1, 1, f);
    fwrite(text_pk, strlen(text_pk), 1, f);
    fwrite(pk_hex, strlen(pk_hex), 1, f);
    fwrite("\n", 1, 1, f);
    fwrite(text_sk, strlen(text_sk), 1, f);
    fwrite(wlist_hex, strlen(wlist_hex), 1, f);
    fwrite(sk_hex, strlen(sk_hex), 1, f);
    fwrite(pk_hex, strlen(pk_hex), 1, f);
    fwrite(sigma_hex, strlen(sigma_hex), 1, f);
    fwrite("\n", 1, 1, f);
    fwrite(text_ct, strlen(text_ct), 1, f);
    fwrite(text_ss, strlen(text_ss), 1, f);
    fclose(f);

    free(seed_hex);
    free(pk_hex);
    free(sk_hex);
    free(wlist_hex);
    free(sigma_hex);
}
