#include <stdlib.h> // malloc, free
#include <stdint.h> // uint8_t
#include <stdio.h> // FILE, fopen, fputs, fclose
#include <string.h> // strlen

#include "internal/bike_defs.h" // R_BYTES, M_BYTES, D
#include "export.h"
#include "util.h" //bin2hex

int export_keys_aws(const char *filename, uint8_t *sk, uint8_t *pk, uint8_t *sigma, uint8_t *seed) {
    char *seed_hex = malloc(2 * 48 + 1);
    char *pk_hex = malloc(2 * R_BYTES + 1);
    char *sk_hex = malloc(2 * (2 * R_BYTES) + 1);
    char *wlist_hex = malloc(2 * (2 * (4 * D)) + 1);
    char *sigma_hex = malloc(2 * M_BYTES + 1);

    bin2hex(seed, seed_hex, 48);
    bin2hex(pk, pk_hex, R_BYTES);
    bin2hex(sk + WLIST_LEN, sk_hex, 2 * R_BYTES);
    bin2hex(sk, wlist_hex, WLIST_LEN);
    bin2hex(sigma, sigma_hex, M_BYTES);

    FILE *f = fopen(filename, "w");
    if (f == NULL) {
        return 1;
    }
    fputs(
"# BIKE\n"
"\n"
"count = 0\n"
"seed = ", f);
    fputs(seed_hex, f);
    fputs(
"\n"
"pk = ", f);
    fputs(pk_hex, f);
    fputs(
"\n"
"sk = ", f);
    fputs(wlist_hex, f);
    fputs(sk_hex, f);
    fputs(pk_hex, f);
    fputs(sigma_hex, f);
    fputs(
"\n"
"ct = *\n"
"ss = *\n", f);
    fclose(f);

    free(seed_hex);
    free(pk_hex);
    free(sk_hex);
    free(wlist_hex);
    free(sigma_hex);
    return 0;
}
